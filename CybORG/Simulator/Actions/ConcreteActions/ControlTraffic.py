from ipaddress import IPv4Address, IPv4Network

from CybORG.Shared import Observation
from CybORG.Simulator.Actions.ConcreteActions.LocalAction import LocalAction
from CybORG.Simulator.State import State

class ControlTraffic(LocalAction):
    """Abstract parent class of all actions that control traffic."""
    def __init__(self, session, agent):
        """ 
        Parameters
        ----------
        session : int
            session id
        agent : str
            agent name
        """
        super().__init__(session, agent)
        self.priority = 1

    def execute(self, state: State) -> Observation:
        """The function that is called when the action is performed/executed.
        
        Checks that the action to be performed is valid (agent and session details)
        
        Parameters
        ----------
        state: State
            current state of the environment
        
        Returns
        -------
        :Observation
        """
        session_is_active = False
        if self.agent in state.sessions and self.session in state.sessions[self.agent]:
            session_is_active = state.sessions[self.agent][self.session].active
        if not session_is_active:
            self.log("No active session found.")
            return Observation(False)
        return self.execute_control_traffic(state)
    
    def execute_control_traffic(self, state: State):
        """Abstract function to be implemented by child class."""
        raise NotImplementedError
    

def _zone_rule(action, state: State):
    """Returns (owner, target): the entry a zone action adds to / removes from state.blocks[owner].
    Without to_host this is the subnet rule (owner to_subnet, target from_subnet).
    With to_host, from_subnet blocks that host in to_subnet (owner from_subnet, target to_host).
    Returns None (after logging why) if the action's arguments are not valid."""
    if action.to_host is None:
        return action.to_subnet, action.from_subnet
    if action.to_host not in state.hostname_subnet_map:
        action.log(f"'{action.to_host}' is not a valid host.")
        return None
    host_subnet = getattr(state.hostname_subnet_map[action.to_host], 'value', state.hostname_subnet_map[action.to_host])
    if host_subnet != action.to_subnet:
        action.log(f"'{action.to_host}' is not in subnet '{action.to_subnet}'.")
        return None
    if action.from_subnet == action.to_subnet:
        action.log(f"'{action.to_host}' is in '{action.from_subnet}'; a subnet can only block a host in another subnet.")
        return None
    return action.from_subnet, action.to_host

class BlockTraffic(ControlTraffic):
    def __init__(self, session: int, agent: str, ip_address: IPv4Address):
        super().__init__(session, agent)
        self.ip_address = ip_address

    def execute_control_traffic(self, state: State) -> Observation:
        hostname = state.sessions[self.agent][self.session].hostname
        other_hostname = state.ip_addresses[self.ip_address]
        if hostname in state.blocks and other_hostname in state.blocks[hostname]:
            self.log(f"'{other_hostname}' is already blocked by '{hostname}'.")
            return Observation(False)
        state.blocks.setdefault(hostname, []).append(other_hostname)
        return Observation(True)

class BlockTrafficZone(ControlTraffic):
    """Action that enables Blue agents to block off access between two subnets in the network. This functionality mimics firewall rules.

    Blocks are two-way: traffic is stopped in both directions between the two sides of the rule.
    By default the rule covers the whole of to_subnet. If to_host is given, from_subnet only blocks that one host
    in to_subnet, and the rest of to_subnet can still talk to from_subnet.
    
    Attributes
    ----------
    from_subnet: str
        name of the subnet doing the blocking
    to_subnet: str
        name of the subnet that is blocked (or that contains the blocked host)
    to_host: str
        optional hostname (in to_subnet) to block instead of the whole of to_subnet
    """
    def __init__(self, session: int, agent: str, from_subnet: str, to_subnet: str, to_host: str = None):
        """
        Parameters
        ----------
        session: int
            session identifier
        agent: str
            name of agent performing action
        from_subnet: str
            name of the subnet doing the blocking
        to_subnet: str
            name of the subnet that is blocked (or that contains the blocked host)
        to_host: str, optional
            hostname in to_subnet to block, instead of the whole subnet
        """
        super().__init__(session, agent)
        self.from_subnet = from_subnet
        self.to_subnet = to_subnet
        self.to_host = to_host

    def execute_control_traffic(self, state: State) -> Observation:
        """Checks for pre-existing blocks, and blocks the connection between the to and from subnet.
        
        Parameters
        ----------
        state: State
            the current state of the environment


        Returns
        -------
        : Observation
            the observation space for this action, holding a true or false success value
        """
        # Check if subnets given are subnets
        if self.from_subnet not in state.subnet_name_to_cidr.keys():
            self.log(f"'{self.from_subnet}' is not a valid subnet.")
            return Observation(False)
        if self.to_subnet not in state.subnet_name_to_cidr.keys():
            self.log(f"'{self.to_subnet}' is not a valid subnet.")
            return Observation(False)
        # The rule covers the whole subnet, or just to_host if one is given
        rule = _zone_rule(self, state)
        if rule is None:
            return Observation(False)
        owner, target = rule
        # Check not already blocked
        if owner in state.blocks and target in state.blocks[owner]:
            self.log(f"'{owner}' is already blocked by '{target}'.")
            return Observation(False)

        state.blocks.setdefault(owner, []).append(target)
        return Observation(True)

class AllowTraffic(ControlTraffic):
    def __init__(self, session: int, agent: str, ip_address: IPv4Address):
        super().__init__(session, agent)
        self.ip_address = ip_address

    def execute_control_traffic(self, state: State) -> Observation:
        hostname = state.sessions[self.agent][self.session].hostname
        other_hostname = state.ip_addresses[self.ip_address]
        if hostname in state.blocks and other_hostname in state.blocks[hostname]:
            state.blocks[hostname].remove(other_hostname)
            return Observation(True)
        self.log(f"'{other_hostname}' is not blocked by '{hostname}'.")
        return Observation(False)

class AllowTrafficZone(ControlTraffic):
    """Action that enables Blue agents to unblock access between two subnets in the network. This functionality mimics reversing firewall rules.

    Removes the rule that BlockTrafficZone added with the same arguments. If to_host is given, only the
    block on that host is removed.
    
    Attributes
    ----------
    from_subnet: str
        name of the subnet that was doing the blocking
    to_subnet: str
        name of the subnet that was blocked (or that contains the blocked host)
    to_host: str
        optional hostname (in to_subnet) whose block should be removed instead of the whole-subnet block
    """
    def __init__(self, session: int, agent: str, from_subnet: str, to_subnet: IPv4Network, to_host: str = None):
        """
        Parameters
        ----------
        session: int
            session identifier
        agent: str
            name of agent performing action
        from_subnet: str
            name of the subnet that was doing the blocking
        to_subnet: str
            name of the subnet that was blocked (or that contains the blocked host)
        to_host: str, optional
            hostname in to_subnet whose block should be removed, instead of the whole subnet
        """
        super().__init__(session, agent)
        self.from_subnet = from_subnet
        self.to_subnet = to_subnet
        self.to_host = to_host

    def execute_control_traffic(self, state: State) -> Observation:
        """Checks for specific pre-existing block, and removes it.
        
        Parameters
        ----------
        state: State
            the current state of the environment


        Returns
        -------
        : Observation
            the observation space for this action, holding a true or false success value
        """
        # Check if subnets given are subnets
        if self.from_subnet not in state.subnet_name_to_cidr.keys():
            self.log(f"'{self.from_subnet}' is not a valid subnet.")
            return Observation(False)
        if self.to_subnet not in state.subnet_name_to_cidr.keys():
            self.log(f"'{self.to_subnet}' is not a valid subnet.")
            return Observation(False)
        rule = _zone_rule(self, state)
        if rule is None:
            return Observation(False)
        owner, target = rule
        # Check there is a block to remove
        if owner in state.blocks and target in state.blocks[owner]:
            state.blocks[owner].remove(target)
            return Observation(True)
        self.log(f"'{owner}' is not blocked by '{target}'.")
        return Observation(False)
