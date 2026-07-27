# Import required base classes and type hinting
from pydantic import BaseModel
from typing import Optional, List

# Define the data schema for network security alerts
class Alert(BaseModel):
    # The origin IP address of the network traffic
    source_ip: str
    
    # The target IP address of the network traffic
    destination_ip: str
    
    # The network port targeted by the traffic
    port: int
    
    # Flag indicating whether the activity is deemed suspicious
    is_suspicious: Optional[bool] = False
    
    # Threat severity categorization (Low / Medium / High)
    risk_level: Optional[str] = "Low"
    
    # Calculated risk score as a percentage from 0.0 to 100.0
    risk_score: Optional[float] = 0.0
    
    # Optional array of numerical features extracted for machine learning evaluation
    features: Optional[List[float]] = None