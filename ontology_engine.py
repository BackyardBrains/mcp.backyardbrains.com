import os
import json
import logging
from pathlib import Path
from datetime import datetime, timezone
from typing import Dict, Any, List, Optional, Union

logger = logging.getLogger(__name__)

class OntologyEngine:
    """
    Engine for interacting with JSON-LD based ontology memory.
    Handles loading, querying, and updating structured graph data.
    """

    def __init__(self, base_path: Union[str, Path]):
        self.base_path = Path(base_path)
        
        # Check if the folders are nested under 'memory/' (as they were locally)
        # or if they are directly in the base_path (as they are on the server)
        if (self.base_path / "memory" / "entities").exists():
            self.entities_path = self.base_path / "memory" / "entities"
            self.schema_path = self.base_path / "memory" / "schema"
        else:
            self.entities_path = self.base_path / "entities"
            self.schema_path = self.base_path / "schema"
        
        # Ensure directories exist (for local testing/setup)
        self.entities_path.mkdir(parents=True, exist_ok=True)
        self.schema_path.mkdir(parents=True, exist_ok=True)

    def _get_file_for_type(self, entity_type: str) -> Path:
        """Map entity type to its JSON-LD file."""
        type_map = {
            "Task": "tasks.jsonld",
            "Requirement": "tasks.jsonld",
            "Project": "projects.jsonld",
            "Person": "persons.jsonld",
            "Event": "events.jsonld",
            "Link": "links.jsonld"
        }
        filename = type_map.get(entity_type, f"{entity_type.lower()}s.jsonld")
        return self.entities_path / filename

    def _load_jsonld(self, file_path: Path) -> Dict[str, Any]:
        """Load and return a JSON-LD file contents."""
        if not file_path.exists():
            return {
                "@context": "../schema/context.jsonld",
                "@graph": []
            }
        try:
            with open(file_path, "r") as f:
                return json.load(f)
        except Exception as e:
            logger.error(f"Failed to load {file_path}: {e}")
            return {"@graph": []}

    def _save_jsonld(self, file_path: Path, data: Dict[str, Any]):
        """Save JSON-LD data to file."""
        try:
            with open(file_path, "w") as f:
                json.dump(data, f, indent=2)
        except Exception as e:
            logger.error(f"Failed to save {file_path}: {e}")
            raise

    def get_entity(self, entity_id: str) -> Optional[Dict[str, Any]]:
        """Get an entity by its @id across all entity files."""
        for file_path in self.entities_path.glob("*.jsonld"):
            data = self._load_jsonld(file_path)
            for entity in data.get("@graph", []):
                if entity.get("@id") == entity_id:
                    return entity
        return None

    def list_entities(self, entity_type: str = None) -> List[Dict[str, Any]]:
        """List all entities, optionally filtered by @type."""
        all_entities = []
        files_to_check = [self._get_file_for_type(entity_type)] if entity_type else self.entities_path.glob("*.jsonld")
        
        for file_path in files_to_check:
            if not file_path.exists():
                continue
            data = self._load_jsonld(file_path)
            for entity in data.get("@graph", []):
                if not entity_type or entity.get("@type") == entity_type:
                    all_entities.append(entity)
        return all_entities

    def upsert_entity(self, entity_data: Dict[str, Any]):
        """Create or update an entity."""
        entity_id = entity_data.get("@id")
        entity_type = entity_data.get("@type")
        
        if not entity_id or not entity_type:
            raise ValueError("Entity must have @id and @type")

        file_path = self._get_file_for_type(entity_type)
        data = self._load_jsonld(file_path)
        graph = data.get("@graph", [])

        updated = False
        for i, entity in enumerate(graph):
            if entity.get("@id") == entity_id:
                graph[i].update(entity_data)
                graph[i]["updatedDate"] = datetime.now(timezone.utc).isoformat()
                updated = True
                break
        
        if not updated:
            entity_data["createdDate"] = datetime.now(timezone.utc).isoformat()
            graph.append(entity_data)

        data["@graph"] = graph
        self._save_jsonld(file_path, data)
        return entity_data

    def delete_entity(self, entity_id: str) -> bool:
        """Delete an entity by its @id."""
        for file_path in self.entities_path.glob("*.jsonld"):
            data = self._load_jsonld(file_path)
            graph = data.get("@graph", [])
            original_len = len(graph)
            
            graph = [e for e in graph if e.get("@id") != entity_id]
            
            if len(graph) < original_len:
                data["@graph"] = graph
                self._save_jsonld(file_path, data)
                return True
        return False

    def query(self, filters: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Simple property-based query across the graph."""
        results = []
        for file_path in self.entities_path.glob("*.jsonld"):
            data = self._load_jsonld(file_path)
            for entity in data.get("@graph", []):
                match = True
                for k, v in filters.items():
                    if entity.get(k) != v:
                        match = False
                        break
                if match:
                    results.append(entity)
        return results

    def relate_entities(self, from_id: str, relation_type: str, to_id: str) -> bool:
        """Create a directed relation between two entities."""
        # Find the source entity
        for file_path in self.entities_path.glob("*.jsonld"):
            data = self._load_jsonld(file_path)
            graph = data.get("@graph", [])
            for i, entity in enumerate(graph):
                if entity.get("@id") == from_id:
                    # Found it, append the relation
                    current_val = entity.get(relation_type)
                    if current_val is None:
                        entity[relation_type] = to_id
                    elif isinstance(current_val, list):
                        if to_id not in current_val:
                            entity[relation_type].append(to_id)
                    else:
                        if current_val != to_id:
                            entity[relation_type] = [current_val, to_id]
                    
                    entity["updatedDate"] = datetime.now(timezone.utc).isoformat()
                    self._save_jsonld(file_path, data)
                    return True
        return False

    def get_related(self, entity_id: str, relation_field: str = None) -> List[Dict[str, Any]]:
        """
        Find entities related to a given ID.
        In JSON-LD, relations are often fields (e.g., 'partOf', 'dependsOn').
        This simple implementation scans typical array or string fields.
        """
        results = []
        for file_path in self.entities_path.glob("*.jsonld"):
            data = self._load_jsonld(file_path)
            for entity in data.get("@graph", []):
                # If specific field is requested
                if relation_field:
                    val = entity.get(relation_field)
                    if val == entity_id or (isinstance(val, list) and entity_id in val):
                        results.append(entity)
                    continue
                
                # Otherwise, scan all fields for the ID
                found = False
                for k, v in entity.items():
                    if k.startswith("@"):
                        continue
                    if v == entity_id or (isinstance(v, list) and entity_id in v):
                        found = True
                        break
                if found:
                    results.append(entity)
        return results

    def get_schema(self) -> str:
        """Read the core.ttl schema file to provide property context to the LLM."""
        schema_file = self.schema_path / "core.ttl"
        if schema_file.exists():
            try:
                with open(schema_file, "r") as f:
                    return f.read()
            except Exception as e:
                logger.error(f"Failed to read schema: {e}")
                return "Error reading schema file."
        return "No core.ttl schema file found."
