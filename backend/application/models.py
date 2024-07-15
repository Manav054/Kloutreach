from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash

db = SQLAlchemy()

class User(db.Model):
    __tablename__ = "users"

    user_id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    email = db.Column(db.String(255), unique=True, nullable=False)
    username = db.Column(db.String(50), unique=True, nullable=False)
    password_hash = db.Column(db.Text, nullable=False)
    approved = db.Column(db.Boolean, default=False)
    active = db.Column(db.Boolean, default=False)
    admin = db.Column(db.Boolean(), default = False)
    role = db.Column(db.String(50), nullable=False)

    influencers = db.relationship("Influencer", backref="user")
    sponsors = db.relationship("Sponsor", backref="user")

    def __init__(self, username, email, password, role, approved = False, admin = False):
        self.username = username
        self.email = email
        self.password_hash = generate_password_hash(password)
        self.role = role
        self.approved = approved
        self.admin = admin

class Sponsor(db.Model):
    __tablename__ = "sponsors"
    sponsor_id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    name = db.Column(db.String(500), unique=True, nullable=False)
    industry = db.Column(db.String(255), nullable=False)
    budget = db.Column(db.Integer, nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey("users.user_id"), nullable = False)
    flagged = db.Column(db.Boolean, default=False)
    campaigns = db.relationship("Campaign", backref="sponsor")

    def __init__(self, name, industry, budget, user_id, flagged = False):
        self.name = name
        self.industry = industry
        self.budget = budget
        self.user_id = user_id
        self.flagged = flagged
      
    def to_dict(self) :
        return {
            "sponsor_id": self.sponsor_id,
            "name": self.name,
            "industry": self.industry,
            "budget": self.budget,
            "user_id": self.user_id,
            "flagged": self.flagged
        }

class Influencer(db.Model):
    __tablename__ = "influencers"

    influencer_id = db.Column(db.Integer, primary_key=True)
    profile_pic = db.Column(db.Text, nullable=False)
    name = db.Column(db.String(255), unique=True, nullable=False)
    category = db.Column(db.String(255), nullable=False)
    niche = db.Column(db.String(255), nullable=False)
    reach = db.Column(db.Text, nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey("users.user_id"), nullable=False)
    flagged = db.Column(db.Boolean, default=False)
    ad_requests = db.relationship("AdRequest", backref="influencer")

    def __init__(self, name, category, link, niche, reach, user_id, flagged = False):
        self.name = name
        self.profile_pic = link
        self.category = category
        self.niche = niche
        self.reach = reach
        self.user_id = user_id
        self.flagged = flagged

    def to_dict(self):
        return {
            "influencer_id" : self.influencer_id,
            "name" : self.name,
            "category" : self.category,
            "niche" : self.niche,
            "reach" : self.reach,
            "user_id" : self.user_id,
            "flagged" : self.flagged
        }
class Campaign(db.Model):
    __tablename__ = "campaigns"

    campaign_id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    name = db.Column(db.String(255), unique=True, nullable=False)
    description = db.Column(db.Text, nullable=False)
    start_date = db.Column(db.Date(), nullable=False)
    end_date = db.Column(db.Date(), nullable=False)
    budget = db.Column(db.Integer, nullable=False)
    visibility = db.Column(db.Text, nullable=False)
    sponsor_id = db.Column(db.Integer, db.ForeignKey("sponsors.sponsor_id"))
    flagged = db.Column(db.Boolean, default=False)

    ad_requests = db.relationship("AdRequest", backref="campaign")

class AdRequest(db.Model):
    __tablename__ = "adRequests"
    request_id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    campaign_id = db.Column(db.Integer, db.ForeignKey("campaigns.campaign_id"), nullable=False)
    influencer_id = db.Column(db.Integer, db.ForeignKey("influencers.influencer_id"), nullable=False)
    messages = db.Column(db.Text, nullable=False)
    requirements = db.Column(db.Text, nullable=False)
    payment_amount = db.Column(db.Integer, nullable=False)
    status = db.Column(db.String(25), default="pending")