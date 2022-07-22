from dataclasses import dataclass
from datetime import date
from typing import Optional

from strawberry.fastapi import GraphQLRouter


@dataclass
class GraphQLVersion:
    version: int
    router: GraphQLRouter
    deprecation_date: Optional[date]
