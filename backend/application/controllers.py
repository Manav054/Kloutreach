from flask import current_app as app
from flask import request, jsonify
from sqlalchemy.exc import IntegrityError
from werkzeug.security import check_password_hash
from email_validator import validate_email, EmailNotValidError
from .models import db, User, Sponsor, Influencer, Campaign, AdRequest
from flask_jwt_extended import JWTManager, jwt_required, create_access_token, get_jwt_identity 

jwt = JWTManager(app)


@app.route("/api/token/validate", methods=["POST"], endpoint="validate")
@jwt_required()
def validate():
    return jsonify({
        "valid": True,
    }), 200

# USER REGISTRATION
@app.route("/api/register", methods = ["POST"])
def user_register():
    try:
        args = request.get_json()
        email = args.get("email")
        username = args.get("username")
        password = args.get("password")
        role = args.get("role")
    except:
        return jsonify({
            "error" : "Invalied JSON format."
        }), 400 #BAD REQUEST    
    
    if not email or not username or not password or not role:
        return jsonify({
            "error" : "Missing required fields!!"
        }), 400 #BAD REQUEST 
    
    try:
        validate_email(email)
    except EmailNotValidError as e:
        return jsonify({
            "Invalid email error" : e
        }), 400 #BAD REQUEST 
    
    if User.query.filter_by(username=username).first() or User.query.filter_by(email=email).first():
        return jsonify({
            "error" : "User already exists!"
        }), 400 #BAD REQUEST 
    
    newUser = User(username = username, email = email, password = password, role = role)
    db.session.add(newUser)
    try:
        db.session.commit()
        return jsonify({
            "message" : "User registered Successfully!"
        }), 201 # CREATED
    except:
        db.session.rollback()
        return jsonify({
            "error" : "Registration Failed!"
        }), 500 # INTERNAL SERVER ERROR
    
# USER LOGIN
@app.route("/api/login/user", methods = ["POST"])
def user_login():
    try:
        args = request.get_json()
        email = args.get("email")
        password = args.get("password")
    except:
        return jsonify({
            "error" : "Invalid JSON format"
        }), 400 # BAD REQUEST
    
    if not email or not password:
        return jsonify({
            "error" : "Missing required fields!!"
        }), 400 #BAD REQUEST 
    
    user = User.query.filter_by(email = email).first()
    if not user:
        return jsonify({
            "error" : "Invalid Credentials!!"
        }), 401 # UNAUTHORIZED ACCESS
    
    if not check_password_hash(user.password_hash, password):
        return jsonify({
            "error" : "Wrong password!"
        }), 401 # UNAUTHORIZED ACCESS
    
    if not user.approved:
        return jsonify({
            "error" : "User not approved!"
        }), 403 # FORBIDDEN
    
    SorI = None
    if user.role == "sponsor":
        SorI = Sponsor.query.filter_by(user_id = user.user_id).first()
        if SorI:
            if SorI.flagged:
                return jsonify({
                    "error" : "You are flagged by the admin. For more information contact admin."
                }), 403 # FORBIDDEN 
    elif user.role == "influencer":
        SorI = Influencer.query.filter_by(user_id = user.user_id).first()
        if SorI:
            if SorI.flagged:
                return jsonify({
                    "error" : "You are flagged by the admin. For more information contact admin."
                }), 403 # FORBIDDEN

    access_token = create_access_token(identity = user.user_id)

    try:
        user.active = 1
        db.session.commit()
    except:
        db.session.rollback()
        return jsonify({
            "error" : "Internal Server Error."
        }), 500 # INTERNAL SERVER ERROR
    if SorI:
        return jsonify({
            "message" : f"Login Successfull for user : {user.user_id}",
            "access_token" : access_token,
            "role" : user.role,
            "SorI" : jsonify(SorI.to_dict())
        }), 200 # SUCCESSFUL
    else :
        return jsonify({
            "message" : f"Login Successfull for user : {user.user_id}",
            "access_token" : access_token,
            "role" : user.role,
            "SorI" : ""
        }), 200 # SUCCESSFUL

# ADMIN LOGIN
@app.route("/api/login/admin", methods = ["POST"])
def admin_login():
    try:
        args = request.get_json()
        email = args.get("email")
        password = args.get("password")
    except:
        return jsonify({
            "error" : "Invalid JSON format"
        }), 400 # BAD REQUEST
    
    if not email or not password:
        return jsonify({
            "error" : "Required fields missing!!"
        }), 400 # BAD REQUEST
    
    user = User.query.filter_by(email=email).first()
    if not user:
        return jsonify({
            "error" : "Invalid Credentials"
        }), 401 # UNAUTHORIZED ACCESS
    
    if not check_password_hash(user.password_hash, password):
        return jsonify({
            "error" : "Wrong password!!"
        }), 401 # UNAUTHORIZED ACCESS
    
    if not user.admin:
        return jsonify({
            "error" : "Unauthorized access!! This login is for admins only."
        }), 403 # FORBIDDEN

    access_token = create_access_token(identity = user.user_id)
    return jsonify({
        "message" : "Login Successfull for Admin.",
        "access_token" : access_token
    }), 200

# GETTING UNAPPROVED USERS
@app.route("/api/user/request", methods=["GET"])
def user_requests():
    try:
        unapproved_users = User.query.filter_by(approved=False).all()
        user_data = [user.to_dict() for user in unapproved_users]
        return jsonify(user_data)
    except Exception as e:
        return jsonify({
            "error" : e
        }), 500 # Internal Server Error
# APPROVING USER
@app.route("/api/approve/<int:user_id>", methods=["PUT"], endpoint = "user_approve")
def user_approve(user_id):
    try:
        user = User.query.filter_by(user_id = user_id).first()

        if not user:
            return jsonify({
                "error" : "User not found!!"
            }), 404 # NOT FOUND
        
        user.approved = True
        db.session.commit()
        return jsonify({
            "message" : "User Approved Successfully."
        }), 200 # OK
    except IntegrityError as e:
        db.session.rollback()
        return jsonify({
            "error" : "An error occured during user update."
        }), 500 # DATABASE ERROR
    except Exception as e:
        return jsonify({
            "error" : str(e)
        }), 500 # INTERNAL SERVER ERROR

# REJECTING USER
@app.route("/api/reject/<int:user_id>", methods=["DELETE"], endpoint="user_reject")
def user_reject(user_id):
    try:
        user = User.query.get(user_id)
        if not user:
            return jsonify({
                "error" : "User not found!"
            }), 404 # NOT FOUND
        
        db.session.delete(user)
        db.session.commit()
        return jsonify({
            "message" : "User rejected successfully!"
        }), 200 # OK
    except IntegrityError as e:
        db.session.rollback()
        return jsonify({
            "error" : "An error occurred in user deletion."
        }), 500 # DATABASE ERROR
    except Exception as e:
        return jsonify({
            "error" : str(e)
        }), 500 # INTERNAL SERVER ERROR
    
# ADDING SPONSOR
@app.route("/api/add/sponsor", methods=["POST"], endpoint="sponser_create")
@jwt_required()
def sponser_create():
    current_user = get_jwt_identity()
    if not current_user:
        return jsonify({
            "error" : "You are not authorized!"
        }), 401 # NOT FOUND

    try:
        args = request.get_json()
        name = args.get("name")
        industry = args.get("industry")
        budget = args.get("budget")
    except:
        return jsonify({
            "error" : "Invalid Json format."
        }), 400 # BAD REQUEST
    
    if not name or not industry or not budget:
        return jsonify({
            "error" : "Required fields missing!"
        }), 400 # BAD REQUEST
    
    try:
        newSponsor = Sponsor(name = name, industry = industry, budget = budget, user_id = current_user)
        db.session.add(newSponsor)
        db.session.commit()
        return jsonify({
            "message" : "Sponser added successfully!"
        }), 201 # CREATED
    except Exception as e:
        db.session.rollback()
        return jsonify({
            "error" : str(e)
        }), 500 # INTERNAL SERVER ERROR

# ADDING INFLUENCER
@app.route("/api/add/influencer", methods=["POST"], endpoint="influencer_create")
@jwt_required()
def influencer_create():
    current_user = get_jwt_identity()
    if not current_user:
        return jsonify({
            "error" : "You are not authorized!"
        }), 401 # NOT FOUND
    try:
        args = request.get_json()
        name = args.get("name")
        category = args.get("category")
        link = args.get("link")
        niche = args.get("niche")
        reach = args.get("reach")
    except:
        return jsonify({
            "error" : "Invalid JSON format."
        }), 400 # BAD REQUEST
    
    if not name or not link or not niche or not reach or not category:
        return jsonify({
            "error" : str(args)
        }), 400 # BAD REQUEST
    
    try:
        newInfluencer = Influencer(name = name, category = category,link = link, niche = niche, reach = reach, user_id = current_user)
        db.session.add(newInfluencer)
        db.session.commit()
        return jsonify({
            "message" : "Influencer created successfully."
        }), 201 # CREATED
    except:
        db.session.rollback()
        return jsonify({
            "error" : "Internal Server Error."
        }), 500 # INTERNAL SERVER ERROR