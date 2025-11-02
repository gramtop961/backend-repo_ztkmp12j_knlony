"""
Database Schemas

Define your MongoDB collection schemas here using Pydantic models.
These schemas are used for data validation in your application.

Each Pydantic model represents a collection in your database.
Model name is converted to lowercase for the collection name:
- User -> "user" collection
- Track -> "track" collection

Note: The Flames database viewer will read these schemas for validation.
"""

from pydantic import BaseModel, Field, EmailStr
from typing import Optional

class User(BaseModel):
    """
    Users collection schema
    Collection name: "user"
    """
    name: Optional[str] = Field(None, description="Full name")
    email: EmailStr = Field(..., description="Email address")
    password_hash: str = Field(..., description="BCrypt hashed password")
    is_active: bool = Field(True, description="Whether user is active")

class Track(BaseModel):
    """
    Tracks collection schema (optional persistence for favorites/playlists)
    Collection name: "track"
    """
    external_id: str = Field(..., description="External provider ID (e.g., iTunes trackId)")
    title: str = Field(..., description="Track title")
    artist: str = Field(..., description="Artist name")
    cover: Optional[str] = Field(None, description="Artwork URL")
    preview_url: Optional[str] = Field(None, description="Short preview/stream URL if available")
    genre: Optional[str] = Field(None, description="Genre name")
