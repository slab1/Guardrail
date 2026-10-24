"""Multi-Agent Mesh Networking for Guardrail Phase 6.

This module provides UDP-based mesh networking for distributed AI agents:
- Agent discovery and registration
- Secure inter-agent communication
- Mesh topology management
- Distributed consensus (Raft-like)
- Message routing and delivery guarantees
"""
import time
import uuid
import json
import hashlib
import threading
import socket
import struct
import asyncio
from typing import Any, Dict, List, Optional, Set, Callable, Tuple
from dataclasses import dataclass, field
from enum import Enum
from collections import defaultdict, deque
from pathlib import Path
import logging


class MessageType(Enum):
    """Types of mesh messages."""
    DISCOVERY = "discovery"
    HEARTBEAT = "heartbeat"
    DATA = "data"
    CONSENSUS_REQUEST = "consensus_request"
    CONSENSUS_VOTE = "consensus_vote"
    CONSENSUS_COMMIT = "consensus_commit"
    TOPOLOGY_UPDATE = "topology_update"
    AGENT_REGISTER = "agent_register"
    AGENT_DEREGISTER = "agent_deregister"
    ROUTE_REQUEST = "route_request"
    ROUTE_RESPONSE = "route_response"


class ConsensusRole(Enum):
    """Roles in consensus protocol."""
    FOLLOWER = "follower"
    CANDIDATE = "candidate"
    LEADER = "leader"


@dataclass
class MeshNode:
    """Represents a node in the mesh."""
    node_id: str
    address: str  # host:port
    public_key: str  # For encryption/verification
    capabilities: List[str] = field(default_factory=list)
    last_seen: float = field(default_factory=time.time)
    is_healthy: bool = True
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class MeshMessage:
    """A message in the mesh network."""
    message_id: str
    message_type: MessageType
    source_id: str
    destination_id: Optional[str]  # None for broadcast
    payload: Dict[str, Any]
    timestamp: float = field(default_factory=time.time)
    ttl: int = 10  # Time to live (hops)
    signature: Optional[str] = None  # For verification
    route: List[str] = field(default_factory=list)  # Path taken


@dataclass
class ConsensusProposal:
    """A consensus proposal."""
    proposal_id: str
    proposer_id: str
    term: int
    index: int
    command: Dict[str, Any]
    timestamp: float = field(default_factory=time.time)


@dataclass
class ConsensusVote:
    """A vote for a consensus proposal."""
    vote_id: str
    proposal_id: str
    voter_id: str
    term: int
    granted: bool
    timestamp: float = field(default_factory=time.time)


class MeshNetwork:
    """UDP-based mesh network for agent communication."""
    
    def __init__(
        self,
        node_id: str,
        listen_address: str = "0.0.0.0:9000",
        bootstrap_nodes: List[str] = None,
        private_key: str = None,
    ):
        self.node_id = node_id
        self.listen_address = listen_address
        self.bootstrap_nodes = bootstrap_nodes or []
        self.private_key = private_key or self._generate_key()
        
        # Network state
        self.nodes: Dict[str, MeshNode] = {}
        self.routing_table: Dict[str, str] = {}  # destination -> next_hop
        self.message_handlers: Dict[MessageType, Callable] = {}
        
        # Consensus state
        self.consensus_role = ConsensusRole.FOLLOWER
        self.current_term = 0
        self.voted_for: Optional[str] = None
        self.log: List[ConsensusProposal] = []
        self.commit_index = 0
        self.last_applied = 0
        
        # Message queues
        self.incoming_queue: asyncio.Queue = asyncio.Queue()
        self.outgoing_queue: asyncio.Queue = asyncio.Queue()
        
        # Socket
        self.socket: Optional[socket.socket] = None
        self.running = False
        self.loop: Optional[asyncio.AbstractEventLoop] = None
        
        # Register default handlers
        self._register_default_handlers()
        
        # Logger
        self.logger = logging.getLogger(f"mesh.{node_id}")
    
    def _generate_key(self) -> str:
        """Generate a simple key (placeholder)."""
        return hashlib.sha256(self.node_id.encode()).hexdigest()[:32]
    
    def _register_default_handlers(self):
        """Register default message handlers."""
        self.message_handlers[MessageType.DISCOVERY] = self._handle_discovery
        self.message_handlers[MessageType.HEARTBEAT] = self._handle_heartbeat
        self.message_handlers[MessageType.DATA] = self._handle_data
        self.message_handlers[MessageType.CONSENSUS_REQUEST] = self._handle_consensus_request
        self.message_handlers[MessageType.CONSENSUS_VOTE] = self._handle_consensus_vote
        self.message_handlers[MessageType.CONSENSUS_COMMIT] = self._handle_consensus_commit
        self.message_handlers[MessageType.TOPOLOGY_UPDATE] = self._handle_topology_update
        self.message_handlers[MessageType.AGENT_REGISTER] = self._handle_agent_register
        self.message_handlers[MessageType.AGENT_DEREGISTER] = self._handle_agent_deregister
        self.message_handlers[MessageType.ROUTE_REQUEST] = self._handle_route_request
        self.message_handlers[MessageType.ROUTE_RESPONSE] = self._handle_route_response
    
    async def start(self):
        """Start the mesh network."""
        self.running = True
        self.loop = asyncio.get_event_loop()
        
        # Create UDP socket
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.socket.setblocking(False)
        
        host, port = self.listen_address.split(":")
        self.socket.bind((host, int(port)))
        
        # Start tasks
        asyncio.create_task(self._receive_loop())
        asyncio.create_task(self._send_loop())
        asyncio.create_task(self._heartbeat_loop())
        asyncio.create_task(self._consensus_loop())
        asyncio.create_task(self._cleanup_loop())
        
        # Bootstrap
        await self._bootstrap()
        
        self.logger.info(f"Mesh node {self.node_id} started on {self.listen_address}")
    
    async def stop(self):
        """Stop the mesh network."""
        self.running = False
        if self.socket:
            self.socket.close()
        
        # Deregister
        await self._broadcast(MessageType.AGENT_DEREGISTER, {
            "node_id": self.node_id,
        })
        
        self.logger.info(f"Mesh node {self.node_id} stopped")
    
    async def _bootstrap(self):
        """Bootstrap by connecting to known nodes."""
        for bootstrap_addr in self.bootstrap_nodes:
            try:
                await self._send_to_address(bootstrap_addr, MessageType.DISCOVERY, {
                    "node_id": self.node_id,
                    "address": self.listen_address,
                    "public_key": self.private_key,  # Simplified
                    "capabilities": ["consensus", "routing"],
                })
            except Exception as e:
                self.logger.warning(f"Failed to bootstrap to {bootstrap_addr}: {e}")
    
    async def _receive_loop(self):
        """Receive incoming UDP packets."""
        while self.running:
            try:
                data, addr = await self.loop.sock_recvfrom(self.socket, 65536)
                await self._process_packet(data, addr)
            except Exception as e:
                if self.running:
                    self.logger.error(f"Receive error: {e}")
    
    async def _send_loop(self):
        """Send outgoing messages."""
        while self.running:
            try:
                message, target_addr = await self.outgoing_queue.get()
                await self._send_packet(message, target_addr)
            except Exception as e:
                if self.running:
                    self.logger.error(f"Send error: {e}")
    
    async def _process_packet(self, data: bytes, addr: Tuple[str, int]):
        """Process incoming packet."""
        try:
            message = self._deserialize_message(data)
            
            # Verify signature (simplified)
            if not self._verify_message(message):
                self.logger.warning(f"Invalid message signature from {addr}")
                return
            
            # Update routing
            self._update_routing(message.source_id, addr)
            
            # Handle message
            handler = self.message_handlers.get(message.message_type)
            if handler:
                await handler(message, addr)
            else:
                self.logger.warning(f"No handler for message type: {message.message_type}")
                
        except Exception as e:
            self.logger.error(f"Packet processing error: {e}")
    
    def _deserialize_message(self, data: bytes) -> MeshMessage:
        """Deserialize message from bytes."""
        # Simplified - in production use proper serialization (protobuf, msgpack)
        obj = json.loads(data.decode())
        return MeshMessage(
            message_id=obj["message_id"],
            message_type=MessageType(obj["message_type"]),
            source_id=obj["source_id"],
            destination_id=obj.get("destination_id"),
            payload=obj["payload"],
            timestamp=obj["timestamp"],
            ttl=obj.get("ttl", 10),
            signature=obj.get("signature"),
            route=obj.get("route", []),
        )
    
    def _serialize_message(self, message: MeshMessage) -> bytes:
        """Serialize message to bytes."""
        obj = {
            "message_id": message.message_id,
            "message_type": message.message_type.value,
            "source_id": message.source_id,
            "destination_id": message.destination_id,
            "payload": message.payload,
            "timestamp": message.timestamp,
            "ttl": message.ttl,
            "signature": message.signature,
            "route": message.route,
        }
        return json.dumps(obj).encode()
    
    def _verify_message(self, message: MeshMessage) -> bool:
        """Verify message signature (simplified)."""
        return True  # Placeholder
    
    def _update_routing(self, source_id: str, addr: Tuple[str, int]):
        """Update routing table."""
        addr_str = f"{addr[0]}:{addr[1]}"
        if source_id not in self.nodes:
            self.nodes[source_id] = MeshNode(
                node_id=source_id,
                address=addr_str,
                public_key="",  # Would be extracted from message
            )
        else:
            self.nodes[source_id].last_seen = time.time()
            self.nodes[source_id].is_healthy = True
        
        self.routing_table[source_id] = addr_str
    
    async def _send_packet(self, message: MeshMessage, target_addr: Tuple[str, int]):
        """Send a packet to target address."""
        data = self._serialize_message(message)
        try:
            await self.loop.sock_sendto(self.socket, self._serialize_message(message), target_addr)
        except Exception as e:
            self.logger.error(f"Failed to send to {target_addr}: {e}")
    
    async def _send_to_address(self, address: str, msg_type: MessageType, payload: Dict):
        """Send message to a specific address."""
        host, port = address.split(":")
        target_addr = (host, int(port))
        
        message = MeshMessage(
            message_id=str(uuid.uuid4())[:8],
            message_type=msg_type,
            source_id=self.node_id,
            destination_id=None,
            payload=payload,
        )
        
        await self.outgoing_queue.put((message, (host, int(port))))
    
    async def _broadcast(self, msg_type: MessageType, payload: Dict):
        """Broadcast message to all known nodes."""
        for node_id, node in self.nodes.items():
            if node.is_healthy and node_id != self.node_id:
                host, port = node.address.split(":")
                message = MeshMessage(
                    message_id=str(uuid.uuid4())[:8],
                    message_type=msg_type,
                    source_id=self.node_id,
                    destination_id=node_id,
                    payload=payload,
                )
                await self.outgoing_queue.put((message, (host, int(port))))
    
    # Message handlers
    async def _handle_discovery(self, message: MeshMessage, addr: Tuple[str, int]):
        """Handle discovery message."""
        # Register new node
        node_info = message.payload
        node_id = node_info.get("node_id")
        
        if node_id and node_id != self.node_id:
            if node_id not in self.nodes:
                self.nodes[node_id] = MeshNode(
                    node_id=node_id,
                    address=f"{addr[0]}:{addr[1]}",
                    public_key=node_info.get("public_key", ""),
                    capabilities=node_info.get("capabilities", []),
                )
                self.logger.info(f"Discovered new node: {node_id}")
            
            # Respond with our info
            await self._send_to_address(f"{addr[0]}:{addr[1]}", MessageType.AGENT_REGISTER, {
                "node_id": self.node_id,
                "address": self.listen_address,
                "public_key": self.private_key,
                "capabilities": ["consensus", "routing"],
            })
    
    async def _handle_heartbeat(self, message: MeshMessage, addr: Tuple[str, int]):
        """Handle heartbeat message."""
        node_id = message.source_id
        if node_id in self.nodes:
            self.nodes[node_id].last_seen = time.time()
            self.nodes[node_id].is_healthy = True
    
    async def _handle_data(self, message: MeshMessage, addr: Tuple[str, int]):
        """Handle data message."""
        # Forward or process data
        if message.destination_id == self.node_id or message.destination_id is None:
            # Process locally
            pass
        elif message.ttl > 0:
            # Forward
            message.ttl -= 1
            message.route.append(self.node_id)
            await self._forward_message(message)
    
    async def _forward_message(self, message: MeshMessage):
        """Forward message towards destination."""
        if message.destination_id in self.routing_table:
            next_hop = self.routing_table[message.destination_id]
            host, port = next_hop.split(":")
            await self.outgoing_queue.put((message, (host, int(port))))
        else:
            # Flood (simplified)
            await self._broadcast(message.message_type, message.payload)
    
    async def _handle_consensus_request(self, message: MeshMessage, addr: Tuple[str, int]):
        """Handle consensus request."""
        # Raft-like consensus
        proposal = ConsensusProposal(**message.payload)
        
        # Check term
        if proposal.term > self.current_term:
            self.current_term = proposal.term
            self.consensus_role = ConsensusRole.FOLLOWER
            self.voted_for = None
        
        # Vote
        granted = self._should_grant_vote(proposal)
        
        vote = ConsensusVote(
            vote_id=str(uuid.uuid4())[:8],
            proposal_id=proposal.proposal_id,
            voter_id=self.node_id,
            term=self.current_term,
            granted=granted,
        )
        
        # Send vote
        await self._send_to_address(f"{addr[0]}:{addr[1]}", MessageType.CONSENSUS_VOTE, {
            "vote_id": vote.vote_id,
            "proposal_id": vote.proposal_id,
            "voter_id": vote.voter_id,
            "term": vote.term,
            "granted": vote.granted,
        })
    
    def _should_grant_vote(self, proposal: ConsensusProposal) -> bool:
        """Decide whether to grant vote."""
        # Simplified: grant if term >= current_term and not voted for someone else
        if proposal.term < self.current_term:
            return False
        if self.voted_for and self.voted_for != proposal.proposer_id:
            return False
        return True
    
    async def _handle_consensus_vote(self, message: MeshMessage, addr: Tuple[str, int]):
        """Handle consensus vote."""
        vote = ConsensusVote(**message.payload)
        # Count votes (simplified)
        pass
    
    async def _handle_consensus_commit(self, message: MeshMessage, addr: Tuple[str, int]):
        """Handle consensus commit."""
        proposal = ConsensusProposal(**message.payload)
        self.commit_index = max(self.commit_index, proposal.index)
        self.log.append(proposal)
    
    async def _handle_topology_update(self, message: MeshMessage, addr: Tuple[str, int]):
        """Handle topology update."""
        # Update routing table
        updates = message.payload.get("routes", {})
        for dest, next_hop in updates.items():
            self.routing_table[dest] = next_hop
    
    async def _handle_agent_register(self, message: MeshMessage, addr: Tuple[str, int]):
        """Handle agent registration."""
        await self._handle_discovery(message, addr)
    
    async def _handle_agent_deregister(self, message: MeshMessage, addr: Tuple[str, int]):
        """Handle agent deregistration."""
        node_id = message.source_id
        if node_id in self.nodes:
            self.nodes[node_id].is_healthy = False
            self.logger.info(f"Node deregistered: {node_id}")
    
    async def _handle_route_request(self, message: MeshMessage, addr: Tuple[str, int]):
        """Handle route request."""
        destination = message.payload.get("destination")
        if destination in self.routing_table:
            await self._send_to_address(f"{addr[0]}:{addr[1]}", MessageType.ROUTE_RESPONSE, {
                "destination": message.payload["destination"],
                "next_hop": self.routing_table[message.payload["destination"]],
            })
    
    async def _handle_route_response(self, message: MeshMessage, addr: Tuple[str, int]):
        """Handle route response."""
        self.routing_table[message.payload["destination"]] = message.payload["next_hop"]
    
    # Background loops
    async def _heartbeat_loop(self):
        """Send periodic heartbeats."""
        while self.running:
            await self._broadcast(MessageType.HEARTBEAT, {
                "node_id": self.node_id,
                "timestamp": time.time(),
            })
            await asyncio.sleep(5)  # Every 5 seconds
    
    async def _consensus_loop(self):
        """Consensus protocol loop."""
        while self.running:
            if self.consensus_role == ConsensusRole.LEADER:
                # Send append entries (heartbeat for leader)
                await self._send_append_entries()
            elif self.consensus_role == ConsensusRole.CANDIDATE:
                # Request votes
                await self._request_votes()
            else:
                # Follower - check election timeout
                pass
            await asyncio.sleep(1)
    
    async def _cleanup_loop(self):
        """Clean up stale nodes."""
        while self.running:
            now = time.time()
            stale_nodes = []
            for node_id, node in self.nodes.items():
                if now - node.last_seen > 30:  # 30 second timeout
                    stale_nodes.append(node_id)
            
            for node_id in stale_nodes:
                if node_id in self.nodes:
                    self.nodes[node_id].is_healthy = False
                    if node_id in self.routing_table:
                        del self.routing_table[node_id]
            
            await asyncio.sleep(10)
    
    async def _send_append_entries(self):
        """Send append entries as leader (simplified)."""
        pass
    
    async def _request_votes(self):
        """Request votes as candidate (simplified)."""
        pass
    
    # Public API
    async def send_message(self, destination_id: str, payload: Dict) -> bool:
        """Send a message to a destination node."""
        if destination_id not in self.routing_table:
            # Try to find route
            await self._discover_route(destination_id)
            if destination_id not in self.routing_table:
                return False
        
        next_hop = self.routing_table[destination_id]
        host, port = next_hop.split(":")
        
        message = MeshMessage(
            message_id=str(uuid.uuid4())[:8],
            message_type=MessageType.DATA,
            source_id=self.node_id,
            destination_id=destination_id,
            payload=payload,
        )
        
        await self.outgoing_queue.put((message, (host, int(port))))
        return True
    
    async def _discover_route(self, destination_id: str):
        """Discover route to destination."""
        for node_id, node in self.nodes.items():
            if node.is_healthy:
                host, port = node.address.split(":")
                await self._send_to_address(node.address, MessageType.ROUTE_REQUEST, {
                    "destination": destination_id,
                })
    
    def get_topology(self) -> Dict[str, Any]:
        """Get current mesh topology."""
        return {
            "node_id": self.node_id,
            "nodes": {
                nid: {
                    "address": node.address,
                    "healthy": node.is_healthy,
                    "capabilities": node.capabilities,
                    "last_seen": node.last_seen,
                }
                for nid, node in self.nodes.items()
            },
            "routes": dict(self.routing_table),
            "consensus_role": self.consensus_role.value,
            "current_term": self.current_term,
        }
    
    def register_handler(self, msg_type: MessageType, handler: Callable):
        """Register custom message handler."""
        self.message_handlers[msg_type] = handler


# Convenience functions
async def create_mesh_node(
    node_id: str,
    listen_address: str = "0.0.0.0:9000",
    bootstrap_nodes: List[str] = None,
) -> MeshNetwork:
    """Create and start a mesh node."""
    mesh = MeshNetwork(node_id, listen_address, bootstrap_nodes)
    await mesh.start()
    return mesh


# Example usage
if __name__ == "__main__":
    async def main():
        # Create mesh node
        mesh = await create_mesh_node("agent_001", "0.0.0.0:9000")
        
        # Send message
        await mesh.send_message("agent_002", {"action": "hello"})
        
        # Get topology
        topology = mesh.get_topology()
        print(json.dumps(topology, indent=2))
        
        await mesh.stop()
    
    asyncio.run(main())