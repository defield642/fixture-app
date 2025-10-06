from flask import Flask, request, jsonify, render_template_string, redirect, url_for, session
from flask_socketio import SocketIO, emit, join_room, leave_room
import json, os, base64, datetime, random, string
from typing import List, Dict, Any
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)
app.secret_key = 'your-secret-key-here-change-in-production'
socketio = SocketIO(app, cors_allowed_origins="*")

SAVE_FILE = "league_state.json"

# Default admin credentials
ADMIN_USERNAME = "admin"
ADMIN_PASSWORD = generate_password_hash("r3wnpLVt7HQaZ9P")

# Track active chats to prevent notification spam
active_chats = {}

# Initialize state
if os.path.exists(SAVE_FILE):
    with open(SAVE_FILE, "r", encoding="utf-8") as f:
        STATE = json.load(f)
        print(f"Loaded state from {SAVE_FILE}")
        print(f"Groups in state: {list(STATE.get('groups', {}).keys())}")
else:
    STATE = {
        "users": {},
        "leagues": {},
        "global_chats": {},
        "private_chats": {},
        "groups": {},
        "status_posts": {},
        "next_league_id": 1,
        "next_group_id": 1,
        "next_status_id": 1,
        "pending_verifications": [],
        "verified_users": []
    }
    print("Created new state")

def ensure_state_structure():
    required_keys = ["users", "leagues", "global_chats", "private_chats", "groups", "status_posts", "next_league_id", "next_group_id", "next_status_id", "pending_verifications", "verified_users"]
    for key in required_keys:
        if key not in STATE:
            print(f"Initializing missing key: {key}")
            if key in ["users", "leagues", "global_chats", "private_chats", "groups", "status_posts"]:
                STATE[key] = {}
            elif key in ["next_league_id", "next_group_id", "next_status_id"]:
                STATE[key] = 1
            elif key in ["pending_verifications", "verified_users"]:
                STATE[key] = []

ensure_state_structure()

def save_state():
    try:
        with open(SAVE_FILE, "w", encoding="utf-8") as f:
            json.dump(STATE, f, ensure_ascii=False, indent=2)
        print(f"State saved. Groups: {list(STATE.get('groups', {}).keys())}")
    except Exception as e:
        print(f"Error saving state: {e}")

# ==== AUTHENTICATION HELPERS ====
def is_logged_in():
    return 'username' in session

def is_admin():
    return session.get('role') == 'admin'

def is_verified():
    username = session.get('username')
    return username in STATE["verified_users"]

def generate_token():
    return ''.join(random.choices(string.ascii_letters + string.digits, k=16))

# ==== USER VERIFICATION ====
def add_pending_verification(username):
    if username not in STATE["pending_verifications"]:
        STATE["pending_verifications"].append(username)
        save_state()

def verify_user(username):
    if username in STATE["pending_verifications"]:
        STATE["pending_verifications"].remove(username)
    if username not in STATE["verified_users"]:
        STATE["verified_users"].append(username)
    save_state()

# ==== USER PROFILE MANAGEMENT ====
def update_user_profile(username, profile_picture, about):
    if username in STATE["users"]:
        if profile_picture:
            STATE["users"][username]["profile_picture"] = profile_picture
        if about:
            STATE["users"][username]["about"] = about
        save_state()
        return True
    return False

# ==== STATUS POSTS ====
def create_status_post(username, content, media_type, media_content):
    status_id = STATE["next_status_id"]
    STATE["next_status_id"] += 1
    
    STATE["status_posts"][str(status_id)] = {
        "id": status_id,
        "username": username,
        "content": content,
        "media_type": media_type,
        "media_content": media_content,
        "timestamp": datetime.datetime.now().isoformat(),
        "likes": [],
        "comments": []
    }
    save_state()
    return status_id

def like_status(status_id, username):
    status = STATE["status_posts"].get(str(status_id))
    if status:
        if username not in status["likes"]:
            status["likes"].append(username)
        else:
            status["likes"].remove(username)
        save_state()
        return True
    return False

def add_comment(status_id, username, comment):
    status = STATE["status_posts"].get(str(status_id))
    if status:
        comment_data = {
            "username": username,
            "comment": comment,
            "timestamp": datetime.datetime.now().isoformat()
        }
        status["comments"].append(comment_data)
        save_state()
        return True
    return False

# ==== GROUP MANAGEMENT - FIXED ====
def create_group(name, description, logo, creator):
    """Create a new group with proper state management"""
    try:
        print(f"Creating group: {name} by {creator}")
        
        # Get next group ID
        group_id = STATE["next_group_id"]
        print(f"Using group ID: {group_id}")
        
        # Create group data
        group_data = {
            "id": group_id,
            "name": name,
            "description": description or "No description",
            "logo": logo,
            "creator": creator,
            "admins": [creator],
            "members": [creator],
            "created_at": datetime.datetime.now().isoformat(),
            "messages": []
        }
        
        # Save to state
        STATE["groups"][str(group_id)] = group_data
        
        # Increment next group ID
        STATE["next_group_id"] = group_id + 1
        
        # Save state
        save_state()
        
        print(f"Group created successfully: {name} (ID: {group_id})")
        print(f"Total groups now: {len(STATE['groups'])}")
        return group_id
        
    except Exception as e:
        print(f"Error creating group: {e}")
        return None

def join_group(group_id, username):
    """Join a group with proper error handling"""
    try:
        group_key = str(group_id)
        print(f"Attempting to join group {group_key} for user {username}")
        
        if group_key not in STATE["groups"]:
            print(f"Group {group_key} not found")
            return False
            
        group = STATE["groups"][group_key]
        print(f"Group found: {group['name']}")
        print(f"Current members: {group['members']}")
        
        if username in group["members"]:
            print(f"User {username} already in group")
            return False
            
        # Add user to group
        group["members"].append(username)
        save_state()
        
        print(f"User {username} successfully joined group {group['name']}")
        print(f"Updated members: {group['members']}")
        return True
        
    except Exception as e:
        print(f"Error joining group: {e}")
        return False

def leave_group(group_id, username):
    group = STATE["groups"].get(str(group_id))
    if group and username in group["members"]:
        group["members"].remove(username)
        if username in group["admins"]:
            group["admins"].remove(username)
        save_state()
        return True
    return False

# ==== LEAGUE MANAGEMENT ====
def create_league(name, game_type, max_teams, logo, reward, creator):
    league_id = STATE["next_league_id"]
    STATE["next_league_id"] += 1
    
    STATE["leagues"][str(league_id)] = {
        "id": league_id,
        "name": name,
        "game_type": game_type,
        "max_teams": max_teams,
        "logo": logo,
        "reward": reward,
        "creator": creator,
        "teams": [],
        "matches": [],
        "status": "open",
        "created_at": datetime.datetime.now().isoformat()
    }
    
    save_state()
    return league_id

def join_league(league_id, username, team_name, team_logo):
    league = STATE["leagues"].get(str(league_id))
    if not league or len(league["teams"]) >= league["max_teams"]:
        return False
    
    if any(team["owner"] == username for team in league["teams"]):
        return False
    
    team_data = {
        "name": team_name,
        "logo": team_logo,
        "owner": username,
        "joined_at": datetime.datetime.now().isoformat()
    }
    
    league["teams"].append(team_data)
    
    if len(league["teams"]) == league["max_teams"]:
        league["matches"] = generate_double_round_robin(league["teams"])
        league["status"] = "ongoing"
    
    save_state()
    return True

# ==== FIXTURE GENERATION ====
def generate_double_round_robin(teams: List[Dict]) -> List[Dict[str, Any]]:
    team_names = [team['name'] for team in teams]
    
    if len(team_names) % 2 == 1:
        team_names.append("BYE")
    
    n = len(team_names)
    rounds = n - 1
    half = n // 2
    schedule = []
    arr = team_names[:]
    match_id = 1

    # first leg
    for r in range(rounds):
        pairings = []
        for i in range(half):
            home = arr[i]
            away = arr[n-1-i]
            if home != "BYE" and away != "BYE":
                home_team = next((t for t in teams if t['name'] == home), {'logo': ''})
                away_team = next((t for t in teams if t['name'] == away), {'logo': ''})
                
                pair = {
                    "id": match_id,
                    "round": r+1,
                    "home": home,
                    "away": away,
                    "home_logo": home_team.get('logo', ''),
                    "away_logo": away_team.get('logo', ''),
                    "home_goals": None,
                    "away_goals": None,
                    "completed": False
                }
                pairings.append(pair)
                match_id += 1
        schedule.extend(pairings)
        arr = [arr[0]] + [arr[-1]] + arr[1:-1]

    # second leg (swap home/away)
    arr = team_names[:]
    for r in range(rounds):
        pairings = []
        for i in range(half):
            home = arr[n-1-i]
            away = arr[i]
            if home != "BYE" and away != "BYE":
                home_team = next((t for t in teams if t['name'] == home), {'logo': ''})
                away_team = next((t for t in teams if t['name'] == away), {'logo': ''})
                
                pair = {
                    "id": match_id,
                    "round": rounds + r + 1,
                    "home": home,
                    "away": away,
                    "home_logo": home_team.get('logo', ''),
                    "away_logo": away_team.get('logo', ''),
                    "home_goals": None,
                    "away_goals": None,
                    "completed": False
                }
                pairings.append(pair)
                match_id += 1
        schedule.extend(pairings)
        arr = [arr[0]] + [arr[-1]] + arr[1:-1]

    return schedule

# ==== TABLE CALCULATION ====
def fresh_row():
    return {"team": "", "logo": "", "MP": 0, "W": 0, "D": 0, "L": 0, "GF": 0, "GA": 0, "GD": 0, "Pts": 0}

def compute_table(teams: List[Dict], matches: List[Dict]) -> List[Dict[str, Any]]:
    table = {}
    
    for team in teams:
        table[team['name']] = {**fresh_row(), "team": team['name'], "logo": team.get('logo', '')}
    
    for m in matches:
        hg, ag = m.get("home_goals"), m.get("away_goals")
        if hg is None or ag is None: 
            continue

        home, away = m["home"], m["away"]
        trh, tra = table[home], table[away]
        trh["MP"] += 1; tra["MP"] += 1
        trh["GF"] += int(hg); trh["GA"] += int(ag)
        tra["GF"] += int(ag); tra["GA"] += int(hg)

        if int(hg) > int(ag):
            trh["W"] += 1; tra["L"] += 1; trh["Pts"] += 3
        elif int(ag) > int(hg):
            tra["W"] += 1; trh["L"] += 1; tra["Pts"] += 3
        else:
            trh["D"] += 1; tra["D"] += 1; trh["Pts"] += 1; tra["Pts"] += 1

    for r in table.values():
        r["GD"] = r["GF"] - r["GA"]

    ordered = sorted(table.values(), key=lambda x: (-x["Pts"], -x["GD"], -x["GF"], x["team"].lower()))
    return ordered

# ==== CHAT MANAGEMENT ====
def get_private_chat_id(user1, user2):
    return f"private_{min(user1, user2)}_{max(user1, user2)}"

def save_private_message(sender, receiver, message, message_type="text", content=None, edited=False, reply_to=None):
    chat_id = get_private_chat_id(sender, receiver)
    
    if chat_id not in STATE["private_chats"]:
        STATE["private_chats"][chat_id] = []
    
    message_data = {
        "id": len(STATE["private_chats"][chat_id]) + 1,
        "sender": sender,
        "receiver": receiver,
        "message": message,
        "type": message_type,
        "content": content,
        "timestamp": datetime.datetime.now().isoformat(),
        "read": False,
        "edited": edited,
        "reply_to": reply_to,
        "deleted": False
    }
    
    STATE["private_chats"][chat_id].append(message_data)
    
    if len(STATE["private_chats"][chat_id]) > 100:
        STATE["private_chats"][chat_id] = STATE["private_chats"][chat_id][-100:]
    
    save_state()
    return message_data

def save_group_message(group_id, sender, message, message_type="text", content=None, edited=False, reply_to=None):
    group = STATE["groups"].get(str(group_id))
    if not group:
        return None
    
    message_data = {
        "id": len(group["messages"]) + 1,
        "sender": sender,
        "message": message,
        "type": message_type,
        "content": content,
        "timestamp": datetime.datetime.now().isoformat(),
        "read_by": [sender],
        "edited": edited,
        "reply_to": reply_to,
        "deleted": False
    }
    
    group["messages"].append(message_data)
    
    if len(group["messages"]) > 100:
        group["messages"] = group["messages"][-100:]
    
    save_state()
    return message_data

# ==== MESSAGE ACTIONS ====
def delete_private_message(chat_id, message_id, username):
    if chat_id in STATE["private_chats"]:
        for message in STATE["private_chats"][chat_id]:
            if message["id"] == message_id and message["sender"] == username:
                message["deleted"] = True
                message["message"] = "This message was deleted"
                message["type"] = "text"
                message["content"] = None
                save_state()
                return True
    return False

def edit_private_message(chat_id, message_id, username, new_message):
    if chat_id in STATE["private_chats"]:
        for message in STATE["private_chats"][chat_id]:
            if message["id"] == message_id and message["sender"] == username:
                message["message"] = new_message
                message["edited"] = True
                save_state()
                return True
    return False

def delete_group_message(group_id, message_id, username):
    group = STATE["groups"].get(str(group_id))
    if group:
        for message in group["messages"]:
            if message["id"] == message_id and message["sender"] == username:
                message["deleted"] = True
                message["message"] = "This message was deleted"
                message["type"] = "text"
                message["content"] = None
                save_state()
                return True
    return False

def edit_group_message(group_id, message_id, username, new_message):
    group = STATE["groups"].get(str(group_id))
    if group:
        for message in group["messages"]:
            if message["id"] == message_id and message["sender"] == username:
                message["message"] = new_message
                message["edited"] = True
                save_state()
                return True
    return False

# ==== PRIVACY HELPER FUNCTIONS ====
def can_user_chat_with(sender_username, receiver_username):
    """Check if a user is allowed to chat with another user"""
    # Admin can chat with anyone
    if sender_username == ADMIN_USERNAME:
        return True
    
    # Users can only chat with verified users or admin
    if (receiver_username in STATE["verified_users"] or 
        receiver_username == ADMIN_USERNAME):
        return True
    
    return False

def get_available_chat_users(current_user):
    """Get list of users that the current user can chat with"""
    available_users = []
    for username in STATE["users"]:
        if (username != current_user and 
            can_user_chat_with(current_user, username)):
            available_users.append(username)
    return available_users

# ==== ROUTES ====
@app.route("/")
def home():
    if not is_logged_in():
        return redirect(url_for('login'))
    
    if not is_verified() and not is_admin():
        return redirect(url_for('pending_verification'))
    
    username = session.get('username')
    user_leagues = []
    available_leagues = []
    user_groups = []
    available_groups = []  # Initialize available_groups
    status_posts = []
    user_chats = []
    
    # Ensure all state structures exist
    ensure_state_structure()
    
    for league_id, league in STATE["leagues"].items():
        if any(team["owner"] == username for team in league["teams"]):
            user_leagues.append(league)
    
    available_leagues = [league for league in STATE["leagues"].values() 
                        if league["status"] == "open" and 
                        not any(team["owner"] == username for team in league["teams"])]
    
    # Get user groups - FIXED
    user_groups = []
    all_groups = STATE.get("groups", {})
    for group_id, group in all_groups.items():
        if username in group.get("members", []):
            user_groups.append(group)
    
    # Get available groups (groups user is NOT in)
    available_groups = []
    for group_id, group in all_groups.items():
        if username not in group.get("members", []):
            available_groups.append(group)
    
    # Get status posts (newest first)
    status_posts = sorted(STATE["status_posts"].values(), key=lambda x: x["timestamp"], reverse=True)
        
    user_chats = []
    if username:
        for chat_id, messages in STATE["private_chats"].items():
            if username in chat_id:
                # Extract the other user from chat_id
                users_in_chat = chat_id.replace('private_', '').split('_')
                other_user = users_in_chat[0] if users_in_chat[1] == username else users_in_chat[1]
                if other_user in STATE["users"] and can_user_chat_with(username, other_user):
                    last_message = messages[-1] if messages else None
                    unread_count = sum(1 for msg in messages if msg.get("receiver") == username and not msg.get("read", False))
                    user_chats.append({
                        "user": other_user,
                        "last_message": last_message,
                        "unread": unread_count
                    })
    
    # Create safe users data structure
    safe_users = {}
    for user_key, user_data in STATE["users"].items():
        if can_user_chat_with(username, user_key):
            safe_users[user_key] = {
                "team_name": user_data.get("team_name", f"{user_key}'s Team"),
                "team_logo": user_data.get("team_logo"),
                "profile_picture": user_data.get("profile_picture"),
                "about": user_data.get("about", ""),
                "joined_at": user_data.get("joined_at", datetime.datetime.now().isoformat())
            }
    
    return render_template_string(HOME_HTML, 
                                username=username,
                                user_leagues=user_leagues,
                                available_leagues=available_leagues,
                                user_groups=user_groups,
                                available_groups=available_groups,  # ADD THIS LINE
                                status_posts=status_posts,
                                users=safe_users,
                                user_chats=user_chats,
                                is_admin=is_admin())

@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form.get("username")
        password = request.form.get("password")
        
        if username == ADMIN_USERNAME and check_password_hash(ADMIN_PASSWORD, password):
            session['username'] = username
            session['role'] = 'admin'
            return redirect(url_for('home'))
        
        user = STATE["users"].get(username)
        if user and check_password_hash(user['password'], password):
            session['username'] = username
            session['role'] = 'user'
            
            if is_verified():
                return redirect(url_for('home'))
            else:
                return redirect(url_for('pending_verification'))
        
        return render_template_string(LOGIN_HTML, error="Invalid credentials")
    
    return render_template_string(LOGIN_HTML)

@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for('login'))

@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        username = request.form.get("username")
        password = request.form.get("password")
        confirm_password = request.form.get("confirm_password")
        team_name = request.form.get("team_name")
        
        if not username or not password:
            return render_template_string(REGISTER_HTML, error="Username and password are required")
        
        if password != confirm_password:
            return render_template_string(REGISTER_HTML, error="Passwords do not match")
        
        if username in STATE["users"]:
            return render_template_string(REGISTER_HTML, error="Username already exists")
        
        # Handle team logo upload
        team_logo = None
        if 'team_logo' in request.files:
            logo_file = request.files['team_logo']
            if logo_file and logo_file.filename:
                team_logo = "data:image/png;base64," + base64.b64encode(logo_file.read()).decode('utf-8')
        
        STATE["users"][username] = {
            "password": generate_password_hash(password),
            "team_name": team_name or f"{username}'s Team",
            "team_logo": team_logo,
            "profile_picture": None,
            "about": "",
            "joined_at": datetime.datetime.now().isoformat(),
            "leagues": []
        }
        
        # Add to pending verifications
        add_pending_verification(username)
        
        save_state()
        
        session['username'] = username
        session['role'] = 'user'
        return redirect(url_for('pending_verification'))
    
    return render_template_string(REGISTER_HTML)

@app.route("/pending_verification")
def pending_verification():
    if not is_logged_in() or is_admin():
        return redirect(url_for('login'))
    
    if is_verified():
        return redirect(url_for('home'))
    
    username = session.get('username')
    return render_template_string(PENDING_VERIFICATION_HTML, username=username)

@app.route("/admin")
def admin_panel():
    if not is_logged_in() or not is_admin():
        return redirect(url_for('login'))
    
    pending_users = STATE["pending_verifications"]
    verified_users = STATE["verified_users"]
    
    return render_template_string(ADMIN_HTML, 
                                pending_users=pending_users,
                                verified_users=verified_users,
                                users=STATE["users"])

@app.route("/admin/verify/<username>")
def admin_verify_user(username):
    if not is_logged_in() or not is_admin():
        return redirect(url_for('login'))
    
    verify_user(username)
    return redirect(url_for('admin_panel'))

@app.route("/profile", methods=["GET", "POST"])
def profile():
    if not is_logged_in():
        return redirect(url_for('login'))
    
    if not is_verified() and not is_admin():
        return redirect(url_for('pending_verification'))
    
    username = session.get('username')
    user = STATE["users"].get(username, {})
    
    # Get user's leagues and groups for stats
    user_leagues = [league for league in STATE["leagues"].values() 
                   if any(team["owner"] == username for team in league["teams"])]
    user_groups = [group for group in STATE["groups"].values() if username in group["members"]]
    status_posts = [post for post in STATE["status_posts"].values() if post["username"] == username]
    
    if request.method == "POST":
        profile_picture = None
        about = request.form.get("about", "")
        
        if 'profile_picture' in request.files:
            picture_file = request.files['profile_picture']
            if picture_file and picture_file.filename:
                profile_picture = "data:image/png;base64," + base64.b64encode(picture_file.read()).decode('utf-8')
        
        if update_user_profile(username, profile_picture, about):
            return redirect(url_for('profile'))
    
    return render_template_string(PROFILE_HTML, 
                                user=user, 
                                username=username,
                                user_leagues=user_leagues,
                                user_groups=user_groups,
                                status_posts=status_posts)

@app.route("/create_league", methods=["GET", "POST"])
def create_league_route():
    if not is_logged_in():
        return redirect(url_for('login'))
    
    if not is_verified() and not is_admin():
        return redirect(url_for('pending_verification'))
    
    if request.method == "POST":
        name = request.form.get("name")
        game_type = request.form.get("game_type")
        reward = request.form.get("reward")
        
        if not name or not game_type:
            return render_template_string(CREATE_LEAGUE_HTML, error="League name and game type are required")
        
        # Handle logo upload
        logo_data = None
        if 'logo' in request.files:
            logo_file = request.files['logo']
            if logo_file and logo_file.filename:
                logo_data = "data:image/png;base64," + base64.b64encode(logo_file.read()).decode('utf-8')
        
        league_id = create_league(
            name=name,
            game_type=game_type,
            max_teams=10,
            logo=logo_data,
            reward=reward,
            creator=session.get('username')
        )
        
        # Creator automatically joins with their team
        user = STATE["users"][session.get('username')]
        join_league(league_id, session.get('username'), user["team_name"], user["team_logo"])
        
        return redirect(url_for('view_league', league_id=league_id))
    
    return render_template_string(CREATE_LEAGUE_HTML)

@app.route("/join_league/<int:league_id>", methods=["POST"])
def join_league_route(league_id):
    if not is_logged_in():
        return jsonify({"error": "Unauthorized"}), 401
    
    if not is_verified() and not is_admin():
        return jsonify({"error": "Not verified"}), 403
    
    username = session.get('username')
    user = STATE["users"][username]
    
    if join_league(league_id, username, user["team_name"], user["team_logo"]):
        return redirect(url_for('view_league', league_id=league_id))
    else:
        return render_template_string(HOME_HTML, 
                                    username=username,
                                    user_leagues=[],
                                    available_leagues=STATE["leagues"].values(),
                                    error="Could not join league. It might be full or you already joined.")

@app.route("/league/<int:league_id>")
def view_league(league_id):
    if not is_logged_in():
        return redirect(url_for('login'))
    
    if not is_verified() and not is_admin():
        return redirect(url_for('pending_verification'))
    
    league = STATE["leagues"].get(str(league_id))
    if not league:
        return "League not found", 404
    
    username = session.get('username')
    user_team = next((team for team in league["teams"] if team["owner"] == username), None)
    table = compute_table(league["teams"], league["matches"])
    rounds = sorted(set(m["round"] for m in league["matches"])) if league["matches"] else []
    
    return render_template_string(LEAGUE_HTML,
                                league=league,
                                user_team=user_team,
                                table=table,
                                rounds=rounds,
                                username=username)

@app.route("/league/<int:league_id>/round/<int:round_num>")
def view_league_round(league_id, round_num):
    if not is_logged_in():
        return redirect(url_for('login'))
    
    if not is_verified() and not is_admin():
        return redirect(url_for('pending_verification'))
    
    league = STATE["leagues"].get(str(league_id))
    if not league:
        return "League not found", 404
    
    matches = [m for m in league["matches"] if m["round"] == round_num]
    rounds = sorted(set(m["round"] for m in league["matches"])) if league["matches"] else []
    
    return render_template_string(LEAGUE_ROUND_HTML,
                                league=league,
                                matches=matches,
                                round_num=round_num,
                                rounds=rounds)

@app.route("/api/update_score", methods=["POST"])
def api_update_score():
    if not is_logged_in():
        return jsonify({"error": "Unauthorized"}), 401
    
    if not is_verified() and not is_admin():
        return jsonify({"error": "Not verified"}), 403
    
    data = request.get_json(force=True)
    league_id = data.get("league_id")
    match_id = data.get("match_id")
    home_goals = data.get("home_goals")
    away_goals = data.get("away_goals")
    
    league = STATE["leagues"].get(str(league_id))
    if not league:
        return jsonify({"error": "League not found"}), 404
    
    match = next((m for m in league["matches"] if m["id"] == match_id), None)
    if not match:
        return jsonify({"error": "Match not found"}), 404
    
    try:
        if home_goals is not None and home_goals != "":
            home_goals = int(home_goals)
            if home_goals < 0 or home_goals > 99:
                raise ValueError()
        else:
            home_goals = None
            
        if away_goals is not None and away_goals != "":
            away_goals = int(away_goals)
            if away_goals < 0 or away_goals > 99:
                raise ValueError()
        else:
            away_goals = None
    except:
        return jsonify({"error": "Scores must be integers between 0 and 99"}), 400
    
    match["home_goals"] = home_goals
    match["away_goals"] = away_goals
    match["completed"] = home_goals is not None and away_goals is not None
    
    save_state()
    return jsonify({"ok": True})

@app.route("/chat")
def chat_main():
    if not is_logged_in():
        return redirect(url_for('login'))
    
    if not is_verified() and not is_admin():
        return redirect(url_for('pending_verification'))
    
    username = session.get('username')
    
    # Only show users that can be chatted with
    users = get_available_chat_users(username)
    
    # Get user's private chats (only with allowed users)
    user_chats = []
    for chat_id, messages in STATE["private_chats"].items():
        if username in chat_id:
            # Extract the other user from chat_id
            users_in_chat = chat_id.replace('private_', '').split('_')
            other_user = users_in_chat[0] if users_in_chat[1] == username else users_in_chat[1]
            if other_user in STATE["users"] and can_user_chat_with(username, other_user):
                last_message = messages[-1] if messages else None
                unread_count = sum(1 for msg in messages if msg.get("receiver") == username and not msg.get("read", False))
                user_chats.append({
                    "user": other_user,
                    "last_message": last_message,
                    "unread": unread_count
                })
    
    return render_template_string(CHAT_MAIN_HTML,
                                username=username,
                                users=users,
                                user_chats=user_chats)

@app.route("/chat/<other_username>")
def private_chat(other_username):
    if not is_logged_in():
        return redirect(url_for('login'))

    if not is_verified() and not is_admin():
        return redirect(url_for('pending_verification'))

    current_user = session.get('username')

    # Block self-chat
    if current_user == other_username:
        return redirect(url_for('chat_main'))

    # Check if the target user exists
    if other_username not in STATE["users"]:
        return "User not found", 404

    # Ensure both users are verified before chatting
    if not can_user_chat_with(current_user, other_username):
        return "You can only chat with verified users", 403

    # Generate chat_id for these two users
    chat_id = get_private_chat_id(current_user, other_username)

    # Ensure chat exists in state
    if chat_id not in STATE["private_chats"]:
        STATE["private_chats"][chat_id] = []
        save_state()

    # Retrieve messages
    messages = STATE["private_chats"].get(chat_id, [])

    # Mark messages as read for the current user
    for message in messages:
        if message.get("receiver") == current_user and not message.get("read", False):
            message["read"] = True
    save_state()

    # Get available users for sidebar
    users = get_available_chat_users(current_user)

    # Build chat list for sidebar
    user_chats = []
    for cid, chat_messages in STATE["private_chats"].items():
        if current_user in cid:
            users_in_chat = cid.replace('private_', '').split('_')
            if len(users_in_chat) < 2:
                continue
            other_user = users_in_chat[0] if users_in_chat[1] == current_user else users_in_chat[1]
            if other_user in STATE["users"] and can_user_chat_with(current_user, other_user):
                last_message = chat_messages[-1] if chat_messages else None
                unread_count = sum(1 for msg in chat_messages if msg.get("receiver") == current_user and not msg.get("read", False))
                user_chats.append({
                    "user": other_user,
                    "last_message": last_message,
                    "unread": unread_count
                })

    other_user_data = STATE["users"].get(other_username, {})

    return render_template_string(PRIVATE_CHAT_HTML,
                                current_user=current_user,
                                other_user=other_username,
                                other_user_data=other_user_data,
                                messages=messages,
                                users=users,
                                user_chats=user_chats,
                                is_admin=is_admin())

@app.route("/groups")
def groups_main():
    if not is_logged_in():
        return redirect(url_for('login'))
    
    if not is_verified() and not is_admin():
        return redirect(url_for('pending_verification'))
    
    username = session.get('username')
    
    # Debug information
    print(f"=== GROUPS DEBUG INFO ===")
    print(f"Current user: {username}")
    print(f"All groups in STATE: {list(STATE.get('groups', {}).keys())}")
    
    # Get user groups
    user_groups = []
    all_groups = STATE.get("groups", {})
    
    for group_id, group in all_groups.items():
        print(f"Checking group {group_id}: {group.get('name')}")
        print(f"Members: {group.get('members', [])}")
        if username in group.get("members", []):
            user_groups.append(group)
            print(f"User is in group {group_id}")
    
    print(f"User groups count: {len(user_groups)}")
    
    # Get available groups (groups user is NOT in)
    available_groups = []
    for group_id, group in all_groups.items():
        if username not in group.get("members", []):
            available_groups.append(group)
            print(f"Group {group_id} is available for user")
    
    print(f"Available groups count: {len(available_groups)}")
    print("=== END DEBUG INFO ===")
    
    return render_template_string(GROUPS_HTML,
                                username=username,
                                user_groups=user_groups,
                                available_groups=available_groups)

@app.route("/create_group", methods=["GET", "POST"])
def create_group_route():
    if not is_logged_in():
        return redirect(url_for('login'))
    
    if not is_verified() and not is_admin():
        return redirect(url_for('pending_verification'))
    
    if request.method == "POST":
        name = request.form.get("name")
        description = request.form.get("description")
        
        print(f"Creating group with name: {name}, description: {description}")
        
        if not name:
            return render_template_string(CREATE_GROUP_HTML, error="Group name is required")
        
        # Handle logo upload
        logo_data = None
        if 'logo' in request.files:
            logo_file = request.files['logo']
            if logo_file and logo_file.filename:
                logo_data = "data:image/png;base64," + base64.b64encode(logo_file.read()).decode('utf-8')
        
        group_id = create_group(
            name=name,
            description=description,
            logo=logo_data,
            creator=session.get('username')
        )
        
        if group_id:
            print(f"Group created successfully with ID: {group_id}")
            return redirect(url_for('view_group', group_id=group_id))
        else:
            return render_template_string(CREATE_GROUP_HTML, error="Failed to create group")
    
    return render_template_string(CREATE_GROUP_HTML)

@app.route("/group/<int:group_id>")
def view_group(group_id):
    if not is_logged_in():
        return redirect(url_for('login'))
    
    if not is_verified() and not is_admin():
        return redirect(url_for('pending_verification'))
    
    group = STATE["groups"].get(str(group_id))
    if not group:
        return "Group not found", 404
    
    username = session.get('username')
    if username not in group.get("members", []):
        return redirect(url_for('groups_main'))
    
    return render_template_string(GROUP_CHAT_HTML,
                                group=group,
                                username=username)

@app.route("/join_group/<int:group_id>")
def join_group_route(group_id):
    if not is_logged_in():
        return redirect(url_for('login'))
    
    if not is_verified() and not is_admin():
        return redirect(url_for('pending_verification'))
    
    username = session.get('username')
    print(f"User {username} attempting to join group {group_id}")
    
    if join_group(group_id, username):
        print(f"Join successful, redirecting to group {group_id}")
        return redirect(url_for('view_group', group_id=group_id))
    else:
        print(f"Join failed for group {group_id}")
        return redirect(url_for('groups_main'))

@app.route("/leave_group/<int:group_id>")
def leave_group_route(group_id):
    if not is_logged_in():
        return redirect(url_for('login'))
    
    if not is_verified() and not is_admin():
        return redirect(url_for('pending_verification'))
    
    username = session.get('username')
    if leave_group(group_id, username):
        return redirect(url_for('groups_main'))
    else:
        return redirect(url_for('view_group', group_id=group_id))

@app.route("/status", methods=["GET", "POST"])
def status_feed():
    if not is_logged_in():
        return redirect(url_for('login'))
    
    if not is_verified() and not is_admin():
        return redirect(url_for('pending_verification'))
    
    username = session.get('username')
    
    if request.method == "POST":
        content = request.form.get("content")
        media_type = "text"
        media_content = None
        
        if 'media' in request.files:
            media_file = request.files['media']
            if media_file and media_file.filename:
                media_content = "data:image/png;base64," + base64.b64encode(media_file.read()).decode('utf-8')
                if media_file.content_type.startswith('video/'):
                    media_type = "video"
                else:
                    media_type = "image"
        
        create_status_post(username, content, media_type, media_content)
        return redirect(url_for('status_feed'))
    
    status_posts = sorted(STATE["status_posts"].values(), key=lambda x: x["timestamp"], reverse=True)
    return render_template_string(STATUS_FEED_HTML,
                                username=username,
                                status_posts=status_posts,
                                users=STATE["users"])

@app.route("/api/like_status", methods=["POST"])
def api_like_status():
    if not is_logged_in():
        return jsonify({"error": "Unauthorized"}), 401
    
    if not is_verified() and not is_admin():
        return jsonify({"error": "Not verified"}), 403
    
    data = request.get_json(force=True)
    status_id = data.get("status_id")
    username = session.get('username')
    
    if like_status(status_id, username):
        status = STATE["status_posts"].get(str(status_id))
        return jsonify({"ok": True, "likes": len(status["likes"]), "liked": username in status["likes"]})
    else:
        return jsonify({"error": "Status not found"}), 404

@app.route("/api/comment_status", methods=["POST"])
def api_comment_status():
    if not is_logged_in():
        return jsonify({"error": "Unauthorized"}), 401
    
    if not is_verified() and not is_admin():
        return jsonify({"error": "Not verified"}), 403
    
    data = request.get_json(force=True)
    status_id = data.get("status_id")
    comment = data.get("comment")
    username = session.get('username')
    
    if add_comment(status_id, username, comment):
        status = STATE["status_posts"].get(str(status_id))
        return jsonify({"ok": True, "comments": status["comments"]})
    else:
        return jsonify({"error": "Status not found"}), 404

# ==== MESSAGE ACTION ROUTES ====
@app.route("/api/delete_private_message", methods=["POST"])
def api_delete_private_message():
    if not is_logged_in():
        return jsonify({"error": "Unauthorized"}), 401
    
    data = request.get_json(force=True)
    chat_id = data.get("chat_id")
    message_id = data.get("message_id")
    username = session.get('username')
    
    if delete_private_message(chat_id, message_id, username):
        return jsonify({"ok": True})
    else:
        return jsonify({"error": "Message not found or unauthorized"}), 404

@app.route("/api/edit_private_message", methods=["POST"])
def api_edit_private_message():
    if not is_logged_in():
        return jsonify({"error": "Unauthorized"}), 401
    
    data = request.get_json(force=True)
    chat_id = data.get("chat_id")
    message_id = data.get("message_id")
    new_message = data.get("new_message")
    username = session.get('username')
    
    if edit_private_message(chat_id, message_id, username, new_message):
        return jsonify({"ok": True})
    else:
        return jsonify({"error": "Message not found or unauthorized"}), 404

@app.route("/api/delete_group_message", methods=["POST"])
def api_delete_group_message():
    if not is_logged_in():
        return jsonify({"error": "Unauthorized"}), 401
    
    data = request.get_json(force=True)
    group_id = data.get("group_id")
    message_id = data.get("message_id")
    username = session.get('username')
    
    if delete_group_message(group_id, message_id, username):
        return jsonify({"ok": True})
    else:
        return jsonify({"error": "Message not found or unauthorized"}), 404

@app.route("/api/edit_group_message", methods=["POST"])
def api_edit_group_message():
    if not is_logged_in():
        return jsonify({"error": "Unauthorized"}), 401
    
    data = request.get_json(force=True)
    group_id = data.get("group_id")
    message_id = data.get("message_id")
    new_message = data.get("new_message")
    username = session.get('username')
    
    if edit_group_message(group_id, message_id, username, new_message):
        return jsonify({"ok": True})
    else:
        return jsonify({"error": "Message not found or unauthorized"}), 404

# ==== SOCKET.IO HANDLERS ====
@socketio.on('connect')
def handle_connect():
    if is_logged_in():
        username = session.get('username')
        join_room(username)
        emit('user_online', {'username': username}, broadcast=True)

@socketio.on('disconnect')
def handle_disconnect():
    if is_logged_in():
        username = session.get('username')
        leave_room(username)
        # Remove from active chats
        if username in active_chats:
            del active_chats[username]
        emit('user_offline', {'username': username}, broadcast=True)

@socketio.on('join_chat')
def handle_join_chat(data):
    """Track when a user opens a chat to prevent notifications"""
    if is_logged_in():
        username = session.get('username')
        other_user = data.get('other_user')
        if username and other_user:
            active_chats[username] = other_user

@socketio.on('leave_chat')
def handle_leave_chat(data):
    """Track when a user leaves a chat"""
    if is_logged_in():
        username = session.get('username')
        if username in active_chats:
            del active_chats[username]

@socketio.on('private_message')
def handle_private_message(data):
    if not is_logged_in():
        return
    
    sender = session.get('username')
    receiver = data.get('receiver')
    
    # Privacy check - ensure receiver exists and sender can only send to valid users
    if receiver not in STATE["users"]:
        return
    
    # Privacy check - users can only message verified users
    if not can_user_chat_with(sender, receiver):
        return
    
    # Prevent self-messaging
    if sender == receiver:
        return
    
    message = data.get('message', '').strip()
    message_type = data.get('type', 'text')
    content = data.get('content')
    reply_to = data.get('reply_to')
    
    if not message and message_type == 'text':
        return
    
    # Save message to state
    message_data = save_private_message(sender, receiver, message, message_type, content, reply_to=reply_to)
    
    # Check if receiver is currently in this chat (to prevent notification spam)
    receiver_in_chat = (receiver in active_chats and active_chats[receiver] == sender)
    
    # Send message to both users with proper data
    emit('new_private_message', {
        'id': message_data['id'],
        'sender': sender,
        'receiver': receiver,
        'message': message,
        'type': message_type,
        'content': content,
        'timestamp': message_data['timestamp'],
        'read': message_data['read'],
        'edited': message_data['edited'],
        'deleted': message_data['deleted'],
        'reply_to': reply_to
    }, room=sender)
    
    emit('new_private_message', {
        'id': message_data['id'],
        'sender': sender,
        'receiver': receiver,
        'message': message,
        'type': message_type,
        'content': content,
        'timestamp': message_data['timestamp'],
        'read': message_data['read'],
        'edited': message_data['edited'],
        'deleted': message_data['deleted'],
        'reply_to': reply_to
    }, room=receiver)
    
    # Only send notification if the receiver is not currently in this chat
    if not receiver_in_chat:
        emit('new_message_notification', {
            'sender': sender,
            'message': message[:50] + '...' if len(message) > 50 else message,
            'timestamp': message_data['timestamp'],
            'chat_with': sender
        }, room=receiver)

@socketio.on('group_message')
def handle_group_message(data):
    if not is_logged_in():
        return
    
    sender = session.get('username')
    group_id = data.get('group_id')
    message = data.get('message', '').strip()
    message_type = data.get('type', 'text')
    content = data.get('content')
    reply_to = data.get('reply_to')
    
    if not message and message_type == 'text':
        return
    
    message_data = save_group_message(group_id, sender, message, message_type, content, reply_to=reply_to)
    if message_data:
        group = STATE["groups"].get(str(group_id))
        # Privacy: Only send to group members
        for member in group["members"]:
            if member != sender:  # Don't send notification to sender
                # Check if member is currently in this group chat
                member_in_group_chat = (member in active_chats and active_chats[member] == f"group_{group_id}")
                
                if not member_in_group_chat:
                    emit('new_message_notification', {
                        'sender': sender,
                        'group_name': group['name'],
                        'message': message[:50] + '...' if len(message) > 50 else message,
                        'timestamp': message_data['timestamp'],
                        'type': 'group',
                        'group_id': group_id
                    }, room=member)
            
            emit('new_group_message', {
                'group_id': group_id,
                'message': message_data
            }, room=member)

@socketio.on('join_group_chat')
def handle_join_group_chat(data):
    if is_logged_in():
        group_id = data.get('group_id')
        username = session.get('username')
        join_room(f"group_{group_id}")
        # Track active group chat
        active_chats[username] = f"group_{group_id}"

@socketio.on('typing')
def handle_typing(data):
    if not is_logged_in():
        return
    
    sender = session.get('username')
    receiver = data.get('receiver')
    
    # Privacy check
    if receiver not in STATE["users"] or not can_user_chat_with(sender, receiver):
        return
    
    is_typing = data.get('typing', False)
    
    emit('user_typing', {
        'sender': sender,
        'typing': is_typing
    }, room=receiver)

@socketio.on('group_typing')
def handle_group_typing(data):
    if not is_logged_in():
        return
    
    sender = session.get('username')
    group_id = data.get('group_id')
    is_typing = data.get('typing', False)
    
    emit('group_user_typing', {
        'sender': sender,
        'group_id': group_id,
        'typing': is_typing
    }, room=f"group_{group_id}")

@socketio.on('mark_as_read')
def handle_mark_as_read(data):
    if not is_logged_in():
        return
    
    username = session.get('username')
    chat_id = data.get('chat_id')
    
    if chat_id in STATE["private_chats"]:
        for message in STATE["private_chats"][chat_id]:
            if message.get("receiver") == username:
                message["read"] = True
        save_state()

@socketio.on('delete_private_message')
def handle_delete_private_message(data):
    if not is_logged_in():
        return
    
    username = session.get('username')
    chat_id = data.get('chat_id')
    message_id = data.get('message_id')
    
    if delete_private_message(chat_id, message_id, username):
        # Notify both users in the chat
        users_in_chat = chat_id.replace('private_', '').split('_')
        for user in users_in_chat:
            emit('message_deleted', {
                'chat_id': chat_id,
                'message_id': message_id
            }, room=user)

@socketio.on('edit_private_message')
def handle_edit_private_message(data):
    if not is_logged_in():
        return
    
    username = session.get('username')
    chat_id = data.get('chat_id')
    message_id = data.get('message_id')
    new_message = data.get('new_message')
    
    if edit_private_message(chat_id, message_id, username, new_message):
        # Notify both users in the chat
        users_in_chat = chat_id.replace('private_', '').split('_')
        for user in users_in_chat:
            emit('message_edited', {
                'chat_id': chat_id,
                'message_id': message_id,
                'new_message': new_message
            }, room=user)

@socketio.on('delete_group_message')
def handle_delete_group_message(data):
    if not is_logged_in():
        return
    
    username = session.get('username')
    group_id = data.get('group_id')
    message_id = data.get('message_id')
    
    if delete_group_message(group_id, message_id, username):
        group = STATE["groups"].get(str(group_id))
        for member in group["members"]:
            emit('message_deleted', {
                'group_id': group_id,
                'message_id': message_id
            }, room=member)

@socketio.on('edit_group_message')
def handle_edit_group_message(data):
    if not is_logged_in():
        return
    
    username = session.get('username')
    group_id = data.get('group_id')
    message_id = data.get('message_id')
    new_message = data.get('new_message')
    
    if edit_group_message(group_id, message_id, username, new_message):
        group = STATE["groups"].get(str(group_id))
        for member in group["members"]:
            emit('message_edited', {
                'group_id': group_id,
                'message_id': message_id,
                'new_message': new_message
            }, room=member)

# ===== TEMPLATES =====
# Updated CHAT_MAIN_HTML with dark mode support
CHAT_MAIN_HTML = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Chat - GEx</title>
    <script src="https://cdn.tailwindcss.com"></script>
    <script src="https://cdnjs.cloudflare.com/ajax/libs/socket.io/4.0.1/socket.io.js"></script>
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css">
    <style>
        :root {
            --bg-primary: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            --bg-secondary: white;
            --text-primary: #374151;
            --text-secondary: #6b7280;
            --border-color: #e5e7eb;
        }

        .dark-mode {
            --bg-primary: linear-gradient(135deg, #1e3a8a 0%, #581c87 100%);
            --bg-secondary: #1f2937;
            --text-primary: #f9fafb;
            --text-secondary: #d1d5db;
            --border-color: #374151;
        }

        body {
            background: var(--bg-primary);
            min-height: 100vh;
            color: var(--text-primary);
            transition: all 0.3s ease;
        }

        .bg-white {
            background-color: var(--bg-secondary) !important;
        }

        .text-gray-800, .text-gray-700, .text-gray-600, .text-gray-500 {
            color: var(--text-primary) !important;
        }

        .border-gray-200, .border-gray-300 {
            border-color: var(--border-color) !important;
        }

        .chat-container {
            height: calc(100vh - 200px);
        }
        .messages-container {
            height: calc(100% - 80px);
            overflow-y: auto;
        }
        .online-dot {
            width: 8px;
            height: 8px;
            background: #10B981;
            border-radius: 50%;
            display: inline-block;
        }
        .unread-badge {
            background: #EF4444;
            color: white;
            border-radius: 50%;
            width: 20px;
            height: 20px;
            display: flex;
            align-items: center;
            justify-content: center;
            font-size: 12px;
        }
        .dark-mode .bg-purple-100 {
            background-color: #4c1d95 !important;
        }
        .dark-mode .bg-green-50 {
            background-color: #065f46 !important;
        }
        .dark-mode .text-purple-700 {
            color: #c4b5fd !important;
        }
    </style>
</head>
<body class="min-h-screen">
    <div class="max-w-6xl mx-auto px-4 py-6">
        <header class="bg-white rounded-2xl shadow-md p-6 mb-6 flex justify-between items-center">
            <div>
                <h1 class="text-3xl font-bold text-purple-800">Chat</h1>
                <p class="text-purple-700">Connect with other players</p>
            </div>
            <div class="flex gap-3">
                <button id="darkModeToggle" class="px-4 py-2 rounded-xl bg-purple-100 text-purple-700 hover:bg-purple-200 transition">
                    <i id="darkModeIcon" class="fas fa-moon mr-2"></i>Theme
                </button>
                <a href="/" class="px-4 py-2 rounded-xl bg-purple-100 text-purple-700 hover:bg-purple-200 transition">
                    <i class="fas fa-home mr-2"></i>Home
                </a>
            </div>
        </header>

        <div class="grid grid-cols-1 lg:grid-cols-4 gap-6">
            <!-- Users List -->
            <div class="bg-white rounded-2xl shadow-md p-4">
                <h3 class="text-lg font-semibold mb-4 text-gray-800">Your Chats</h3>
                <div class="space-y-2 max-h-96 overflow-y-auto">
                    {% for chat in user_chats %}
                    <a href="/chat/{{ chat.user }}" class="block p-3 rounded-lg hover:bg-purple-50 transition border border-gray-100">
                        <div class="flex items-center justify-between">
                            <div class="flex items-center">
                                <span class="online-dot mr-2"></span>
                                <span class="font-medium text-gray-800">{{ chat.user }}</span>
                            </div>
                            {% if chat.unread > 0 %}
                            <div class="unread-badge">
                                {{ chat.unread }}
                            </div>
                            {% endif %}
                        </div>
                        {% if chat.last_message %}
                        <p class="text-sm text-gray-600 truncate mt-1">{{ chat.last_message.message }}</p>
                        {% endif %}
                    </a>
                    {% endfor %}
                </div>

                <!-- Start New Chat -->
                <div class="mt-4 pt-4 border-t border-gray-200">
                    <h3 class="text-md font-semibold mb-2 text-gray-800">Start New Chat</h3>
                    <div class="space-y-2 max-h-48 overflow-y-auto">
                        {% for user in users %}
                        <a href="/chat/{{ user }}" class="block p-2 rounded-lg hover:bg-green-50 transition">
                            <div class="flex items-center">
                                <span class="online-dot mr-2"></span>
                                <span class="font-medium text-gray-800 text-sm">{{ user }}</span>
                            </div>
                        </a>
                        {% endfor %}
                    </div>
                </div>
            </div>

            <!-- Chat Area -->
            <div class="lg:col-span-3">
                <div class="bg-white rounded-2xl shadow-md chat-container flex flex-col">
                    <div class="flex-1 flex items-center justify-center p-8">
                        <div class="text-center text-gray-500">
                            <i class="fas fa-comments text-4xl mb-4 text-purple-300"></i>
                            <h3 class="text-xl font-semibold mb-2">Welcome to Chat</h3>
                            <p class="mb-4">Select a user from the sidebar to start chatting</p>
                            <p class="text-sm">Your messages are private and secure</p>
                        </div>
                    </div>
                </div>
            </div>
        </div>
    </div>

    <script>
        const socket = io();
        const currentUser = "{{ username }}";

        // Dark mode functionality
        function initializeDarkMode() {
            const darkModeToggle = document.getElementById('darkModeToggle');
            const darkModeIcon = document.getElementById('darkModeIcon');
            const isDarkMode = localStorage.getItem('darkMode') === 'true';
            
            if (isDarkMode) {
                document.body.classList.add('dark-mode');
                darkModeIcon.classList.replace('fa-moon', 'fa-sun');
            }
            
            darkModeToggle.addEventListener('click', () => {
                document.body.classList.toggle('dark-mode');
                const isNowDark = document.body.classList.contains('dark-mode');
                
                if (isNowDark) {
                    darkModeIcon.classList.replace('fa-moon', 'fa-sun');
                } else {
                    darkModeIcon.classList.replace('fa-sun', 'fa-moon');
                }
                
                localStorage.setItem('darkMode', isNowDark);
            });
        }

        // Connect to socket
        socket.emit('user_online', {username: currentUser});

        // Handle new message notifications
        socket.on('new_message_notification', function(data) {
            // Refresh the page to update unread counts
            setTimeout(() => {
                window.location.reload();
            }, 1000);
        });

        // Initialize dark mode
        document.addEventListener('DOMContentLoaded', initializeDarkMode);
    </script>
</body>
</html>
"""

# Updated PRIVATE_CHAT_HTML with message actions and dark mode
PRIVATE_CHAT_HTML = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Chat with {{ other_user }} - GEx</title>
    <script src="https://cdn.tailwindcss.com"></script>
    <script src="https://cdnjs.cloudflare.com/ajax/libs/socket.io/4.0.1/socket.io.js"></script>
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css">
    <style>
        :root {
            --bg-primary: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            --bg-secondary: white;
            --text-primary: #374151;
            --text-secondary: #6b7280;
            --border-color: #e5e7eb;
        }

        .dark-mode {
            --bg-primary: linear-gradient(135deg, #1e3a8a 0%, #581c87 100%);
            --bg-secondary: #1f2937;
            --text-primary: #f9fafb;
            --text-secondary: #d1d5db;
            --border-color: #374151;
        }

        body {
            background: var(--bg-primary);
            min-height: 100vh;
            color: var(--text-primary);
            transition: all 0.3s ease;
        }

        .bg-white {
            background-color: var(--bg-secondary) !important;
        }

        .text-gray-800, .text-gray-700, .text-gray-600, .text-gray-500 {
            color: var(--text-primary) !important;
        }

        .border-gray-200, .border-gray-300 {
            border-color: var(--border-color) !important;
        }

        .chat-container {
            height: calc(100vh - 200px);
        }
        .messages-container {
            height: calc(100% - 80px);
            overflow-y: auto;
        }
        .message-self {
            background-color: #e9d5ff;
            margin-left: auto;
            max-width: 70%;
            position: relative;
        }
        .message-other {
            background-color: #f3f4f6;
            max-width: 70%;
            position: relative;
        }
        .dark-mode .message-other {
            background-color: #374151;
        }
        .typing-indicator {
            display: none;
        }
        .online-dot {
            width: 8px;
            height: 8px;
            background: #10B981;
            border-radius: 50%;
            display: inline-block;
        }
        .message-actions {
            display: none;
            position: absolute;
            top: -40px;
            right: 0;
            background: var(--bg-secondary);
            border: 1px solid var(--border-color);
            border-radius: 8px;
            box-shadow: 0 4px 12px rgba(0,0,0,0.15);
            z-index: 100;
        }
        .message:hover .message-actions {
            display: flex;
        }
        .action-btn {
            padding: 8px 12px;
            border: none;
            background: none;
            cursor: pointer;
            color: var(--text-primary);
            transition: background-color 0.2s;
        }
        .action-btn:hover {
            background-color: var(--border-color);
        }
        .edit-input {
            width: 100%;
            padding: 8px;
            border: 1px solid var(--border-color);
            border-radius: 4px;
            background: var(--bg-secondary);
            color: var(--text-primary);
        }
        .dark-mode .bg-purple-100 {
            background-color: #4c1d95 !important;
        }
        .dark-mode .bg-green-50 {
            background-color: #065f46 !important;
        }
        .dark-mode .text-purple-700 {
            color: #c4b5fd !important;
        }
        .reply-indicator {
            background: var(--border-color);
            padding: 8px;
            border-radius: 8px;
            margin-bottom: 8px;
            font-size: 0.9em;
            border-left: 3px solid #667eea;
        }
    </style>
</head>
<body class="min-h-screen">
    <div class="max-w-6xl mx-auto px-4 py-6">
        <header class="bg-white rounded-2xl shadow-md p-6 mb-6 flex justify-between items-center">
            <div class="flex items-center">
                <a href="/chat" class="mr-4 px-3 py-2 rounded-lg bg-purple-100 text-purple-700 hover:bg-purple-200 transition">
                    <i class="fas fa-arrow-left"></i>
                </a>
                <div class="flex items-center">
                    {% if other_user_data.profile_picture %}
                    <img src="{{ other_user_data.profile_picture }}" class="w-12 h-12 rounded-full mr-3">
                    {% else %}
                    <div class="w-12 h-12 rounded-full bg-purple-100 flex items-center justify-center mr-3">
                        <i class="fas fa-user text-purple-600"></i>
                    </div>
                    {% endif %}
                    <div>
                        <h1 class="text-2xl font-bold text-purple-800">{{ other_user }}</h1>
                        <div class="flex items-center">
                            <span class="online-dot mr-2"></span>
                            <p class="text-purple-700 text-sm">Online</p>
                        </div>
                    </div>
                </div>
            </div>
            <div class="flex gap-3">
                <button id="darkModeToggle" class="px-4 py-2 rounded-xl bg-purple-100 text-purple-700 hover:bg-purple-200 transition">
                    <i id="darkModeIcon" class="fas fa-moon mr-2"></i>Theme
                </button>
                <a href="/" class="px-4 py-2 rounded-xl bg-purple-100 text-purple-700 hover:bg-purple-200 transition">
                    <i class="fas fa-home mr-2"></i>Home
                </a>
            </div>
        </header>

        <div class="grid grid-cols-1 lg:grid-cols-4 gap-6">
            <!-- Users List -->
            <div class="bg-white rounded-2xl shadow-md p-4">
                <h3 class="text-lg font-semibold mb-4 text-gray-800">Your Chats</h3>
                <div class="space-y-2 max-h-96 overflow-y-auto">
                    {% for chat in user_chats %}
                    <a href="/chat/{{ chat.user }}" class="block p-3 rounded-lg hover:bg-purple-50 transition border border-gray-100 {{ 'bg-purple-100' if chat.user == other_user else '' }}">
                        <div class="flex items-center justify-between">
                            <div class="flex items-center">
                                <span class="online-dot mr-2"></span>
                                <span class="font-medium text-gray-800">{{ chat.user }}</span>
                            </div>
                            {% if chat.unread > 0 %}
                            <div class="unread-badge">
                                {{ chat.unread }}
                            </div>
                            {% endif %}
                        </div>
                        {% if chat.last_message %}
                        <p class="text-sm text-gray-600 truncate mt-1">{{ chat.last_message.message }}</p>
                        {% endif %}
                    </a>
                    {% endfor %}
                </div>

                <!-- Start New Chat -->
                <div class="mt-4 pt-4 border-t border-gray-200">
                    <h3 class="text-md font-semibold mb-2 text-gray-800">Start New Chat</h3>
                    <div class="space-y-2 max-h-48 overflow-y-auto">
                        {% for user in users %}
                        <a href="/chat/{{ user }}" class="block p-2 rounded-lg hover:bg-green-50 transition">
                            <div class="flex items-center">
                                <span class="online-dot mr-2"></span>
                                <span class="font-medium text-gray-800 text-sm">{{ user }}</span>
                            </div>
                        </a>
                        {% endfor %}
                    </div>
                </div>
            </div>

            <!-- Chat Area -->
            <div class="lg:col-span-3">
                <div class="bg-white rounded-2xl shadow-md chat-container flex flex-col">
                    <!-- Chat Header -->
                    <div class="p-4 border-b">
                        <div class="flex items-center justify-between">
                            <div class="flex items-center">
                                <span class="online-dot mr-2"></span>
                                <span class="font-semibold text-gray-800">{{ other_user }}</span>
                                <div id="typingIndicator" class="typing-indicator ml-2 text-sm text-gray-500">
                                    is typing...
                                </div>
                            </div>
                            <div class="text-sm text-gray-500">
                                Private Chat • End-to-end encrypted
                            </div>
                        </div>
                    </div>

                    <!-- Messages -->
                    <div id="messagesContainer" class="messages-container p-4 space-y-3">
                        {% for message in messages %}
                        <div class="flex {{ 'justify-end' if message.sender == current_user else 'justify-start' }} message" data-message-id="{{ message.id }}">
                            <div class="max-w-xs md:max-w-md rounded-lg p-3 {{ 'message-self' if message.sender == current_user else 'message-other' }}">
                                {% if message.reply_to %}
                                <div class="reply-indicator text-sm text-gray-600 mb-2">
                                    <i class="fas fa-reply mr-1"></i>
                                    Replying to: {{ message.reply_to.message|truncate(30) }}
                                </div>
                                {% endif %}
                                
                                {% if message.deleted %}
                                <div class="text-gray-500 italic">This message was deleted</div>
                                {% else %}
                                    {% if message.type == 'text' %}
                                    <div class="text-gray-800 message-content">{{ message.message }}</div>
                                    {% elif message.type == 'image' %}
                                    <img src="{{ message.content }}" class="max-w-full rounded" alt="Shared image">
                                    {% endif %}
                                {% endif %}
                                
                                <div class="flex items-center justify-between mt-1">
                                    <div class="text-xs text-gray-500">
                                        {{ message.timestamp[11:16] }}
                                        {% if message.edited %}
                                        <span class="italic">(edited)</span>
                                        {% endif %}
                                    </div>
                                </div>
                                
                                <!-- Message Actions -->
                                {% if message.sender == current_user and not message.deleted %}
                                <div class="message-actions">
                                    <button class="action-btn copy-btn" title="Copy">
                                        <i class="fas fa-copy"></i>
                                    </button>
                                    <button class="action-btn edit-btn" title="Edit">
                                        <i class="fas fa-edit"></i>
                                    </button>
                                    <button class="action-btn delete-btn" title="Delete">
                                        <i class="fas fa-trash"></i>
                                    </button>
                                    <button class="action-btn reply-btn" title="Reply">
                                        <i class="fas fa-reply"></i>
                                    </button>
                                </div>
                                {% elif not message.deleted %}
                                <div class="message-actions">
                                    <button class="action-btn copy-btn" title="Copy">
                                        <i class="fas fa-copy"></i>
                                    </button>
                                    <button class="action-btn reply-btn" title="Reply">
                                        <i class="fas fa-reply"></i>
                                    </button>
                                </div>
                                {% endif %}
                            </div>
                        </div>
                        {% endfor %}
                    </div>

                    <!-- Reply Indicator -->
                    <div id="replyIndicator" class="hidden p-3 border-b bg-gray-50">
                        <div class="flex justify-between items-center">
                            <div>
                                <span class="text-sm text-gray-600">Replying to:</span>
                                <span id="replyPreview" class="text-sm ml-2"></span>
                            </div>
                            <button id="cancelReply" class="text-gray-500 hover:text-gray-700">
                                <i class="fas fa-times"></i>
                            </button>
                        </div>
                    </div>

                    <!-- Message Input -->
                    <div class="p-4 border-t">
                        <div class="flex gap-2">
                            <input type="text" id="messageInput" placeholder="Type your message..." 
                                class="flex-1 p-3 border border-gray-300 rounded-lg focus:ring-2 focus:ring-purple-500 focus:border-purple-500">
                            
                            <!-- File Upload Button -->
                            <label for="fileInput" class="px-4 py-3 bg-gray-600 text-white rounded-lg hover:bg-gray-700 transition cursor-pointer">
                                <i class="fas fa-paperclip"></i>
                            </label>
                            <input type="file" id="fileInput" accept="image/*" class="hidden">
                            
                            <button id="sendMessage" class="px-4 py-3 bg-purple-600 text-white rounded-lg hover:bg-purple-700 transition">
                                <i class="fas fa-paper-plane"></i>
                            </button>
                        </div>
                    </div>
                </div>
            </div>
        </div>
    </div>

    <script>
        const socket = io();
        const currentUser = "{{ current_user }}";
        const otherUser = "{{ other_user }}";
        const chatId = `private_${currentUser < otherUser ? currentUser : otherUser}_${currentUser > otherUser ? currentUser : otherUser}`;
        
        let replyingTo = null;
        let editingMessageId = null;

        // Dark mode functionality
        function initializeDarkMode() {
            const darkModeToggle = document.getElementById('darkModeToggle');
            const darkModeIcon = document.getElementById('darkModeIcon');
            const isDarkMode = localStorage.getItem('darkMode') === 'true';
            
            if (isDarkMode) {
                document.body.classList.add('dark-mode');
                darkModeIcon.classList.replace('fa-moon', 'fa-sun');
            }
            
            darkModeToggle.addEventListener('click', () => {
                document.body.classList.toggle('dark-mode');
                const isNowDark = document.body.classList.contains('dark-mode');
                
                if (isNowDark) {
                    darkModeIcon.classList.replace('fa-moon', 'fa-sun');
                } else {
                    darkModeIcon.classList.replace('fa-sun', 'fa-moon');
                }
                
                localStorage.setItem('darkMode', isNowDark);
            });
        }

        // Connect to personal room
        socket.emit('user_online', {username: currentUser});
        
        // Join this specific chat
        socket.emit('join_chat', {other_user: otherUser});

        // Scroll to bottom of messages
        function scrollToBottom() {
            const container = document.getElementById('messagesContainer');
            container.scrollTop = container.scrollHeight;
        }

        // Send message
        function sendMessage() {
            const messageInput = document.getElementById('messageInput');
            const message = messageInput.value.trim();
            
            if (message) {
                const messageData = {
                    receiver: otherUser,
                    message: message,
                    type: 'text'
                };
                
                if (replyingTo) {
                    messageData.reply_to = replyingTo;
                }
                
                if (editingMessageId) {
                    // Edit existing message
                    socket.emit('edit_private_message', {
                        chat_id: chatId,
                        message_id: editingMessageId,
                        new_message: message
                    });
                    editingMessageId = null;
                } else {
                    // Send new message
                    socket.emit('private_message', messageData);
                }
                
                messageInput.value = '';
                cancelReply();
            }
        }

        // Handle incoming messages
        socket.on('new_private_message', function(data) {
            if ((data.sender === currentUser && data.receiver === otherUser) || 
                (data.sender === otherUser && data.receiver === currentUser)) {
                
                addMessageToUI(data);
                scrollToBottom();
            }
        });

        // Handle message edits
        socket.on('message_edited', function(data) {
            if (data.chat_id === chatId) {
                const messageElement = document.querySelector(`[data-message-id="${data.message_id}"]`);
                if (messageElement) {
                    const contentElement = messageElement.querySelector('.message-content');
                    if (contentElement) {
                        contentElement.textContent = data.new_message;
                    }
                    const timestampElement = messageElement.querySelector('.text-xs');
                    if (timestampElement && !timestampElement.innerHTML.includes('edited')) {
                        timestampElement.innerHTML += ' <span class="italic">(edited)</span>';
                    }
                }
            }
        });

        // Handle message deletion
        socket.on('message_deleted', function(data) {
            if (data.chat_id === chatId) {
                const messageElement = document.querySelector(`[data-message-id="${data.message_id}"]`);
                if (messageElement) {
                    const contentElement = messageElement.querySelector('.message-content');
                    if (contentElement) {
                        contentElement.innerHTML = '<span class="italic text-gray-500">This message was deleted</span>';
                    }
                    // Hide action buttons for deleted messages
                    const actionButtons = messageElement.querySelector('.message-actions');
                    if (actionButtons) {
                        actionButtons.style.display = 'none';
                    }
                }
            }
        });

        // Add message to UI
        function addMessageToUI(data) {
            const messagesContainer = document.getElementById('messagesContainer');
            const messageDiv = document.createElement('div');
            messageDiv.className = `flex ${data.sender === currentUser ? 'justify-end' : 'justify-start'} message`;
            messageDiv.setAttribute('data-message-id', data.id);
            
            let messageContent = '';
            if (data.deleted) {
                messageContent = '<div class="text-gray-500 italic">This message was deleted</div>';
            } else if (data.type === 'text') {
                messageContent = `<div class="text-gray-800 message-content">${data.message}</div>`;
            } else if (data.type === 'image') {
                messageContent = `<img src="${data.content}" class="max-w-full rounded" alt="Shared image">`;
            }
            
            let replySection = '';
            if (data.reply_to) {
                replySection = `
                    <div class="reply-indicator text-sm text-gray-600 mb-2">
                        <i class="fas fa-reply mr-1"></i>
                        Replying to: ${data.reply_to.message ? data.reply_to.message.substring(0, 30) + (data.reply_to.message.length > 30 ? '...' : '') : 'Message'}
                    </div>
                `;
            }
            
            let actionButtons = '';
            if (data.sender === currentUser && !data.deleted) {
                actionButtons = `
                    <div class="message-actions">
                        <button class="action-btn copy-btn" title="Copy">
                            <i class="fas fa-copy"></i>
                        </button>
                        <button class="action-btn edit-btn" title="Edit">
                            <i class="fas fa-edit"></i>
                        </button>
                        <button class="action-btn delete-btn" title="Delete">
                            <i class="fas fa-trash"></i>
                        </button>
                        <button class="action-btn reply-btn" title="Reply">
                            <i class="fas fa-reply"></i>
                        </button>
                    </div>
                `;
            } else if (!data.deleted) {
                actionButtons = `
                    <div class="message-actions">
                        <button class="action-btn copy-btn" title="Copy">
                            <i class="fas fa-copy"></i>
                        </button>
                        <button class="action-btn reply-btn" title="Reply">
                            <i class="fas fa-reply"></i>
                        </button>
                    </div>
                `;
            }
            
            messageDiv.innerHTML = `
                <div class="max-w-xs md:max-w-md rounded-lg p-3 ${data.sender === currentUser ? 'message-self' : 'message-other'}">
                    ${replySection}
                    ${messageContent}
                    <div class="flex items-center justify-between mt-1">
                        <div class="text-xs text-gray-500">
                            ${new Date(data.timestamp).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })}
                            ${data.edited ? '<span class="italic">(edited)</span>' : ''}
                        </div>
                    </div>
                    ${actionButtons}
                </div>
            `;
            
            messagesContainer.appendChild(messageDiv);
            attachMessageActions(messageDiv, data);
        }

        // Attach action handlers to message
        function attachMessageActions(messageElement, messageData) {
            // Copy button
            const copyBtn = messageElement.querySelector('.copy-btn');
            if (copyBtn) {
                copyBtn.addEventListener('click', () => {
                    if (!messageData.deleted) {
                        navigator.clipboard.writeText(messageData.message);
                        // Show copied feedback
                        const originalHTML = copyBtn.innerHTML;
                        copyBtn.innerHTML = '<i class="fas fa-check"></i>';
                        setTimeout(() => {
                            copyBtn.innerHTML = originalHTML;
                        }, 1000);
                    }
                });
            }

            // Edit button
            const editBtn = messageElement.querySelector('.edit-btn');
            if (editBtn) {
                editBtn.addEventListener('click', () => {
                    if (!messageData.deleted) {
                        editingMessageId = messageData.id;
                        document.getElementById('messageInput').value = messageData.message;
                        document.getElementById('messageInput').focus();
                    }
                });
            }

            // Delete button
            const deleteBtn = messageElement.querySelector('.delete-btn');
            if (deleteBtn) {
                deleteBtn.addEventListener('click', () => {
                    if (!messageData.deleted && confirm('Are you sure you want to delete this message?')) {
                        socket.emit('delete_private_message', {
                            chat_id: chatId,
                            message_id: messageData.id
                        });
                    }
                });
            }

            // Reply button
            const replyBtn = messageElement.querySelector('.reply-btn');
            if (replyBtn) {
                replyBtn.addEventListener('click', () => {
                    if (!messageData.deleted) {
                        replyingTo = {
                            id: messageData.id,
                            message: messageData.message,
                            sender: messageData.sender
                        };
                        showReplyIndicator(messageData);
                    }
                });
            }
        }

        // Show reply indicator
        function showReplyIndicator(messageData) {
            const replyIndicator = document.getElementById('replyIndicator');
            const replyPreview = document.getElementById('replyPreview');
            
            replyPreview.textContent = messageData.message.substring(0, 50) + (messageData.message.length > 50 ? '...' : '');
            replyIndicator.classList.remove('hidden');
            
            document.getElementById('messageInput').focus();
        }

        // Cancel reply
        function cancelReply() {
            replyingTo = null;
            editingMessageId = null;
            const replyIndicator = document.getElementById('replyIndicator');
            replyIndicator.classList.add('hidden');
        }

        // Typing indicators
        let typingTimer;
        document.getElementById('messageInput').addEventListener('input', function() {
            socket.emit('typing', {
                receiver: otherUser,
                typing: true
            });
            
            clearTimeout(typingTimer);
            typingTimer = setTimeout(() => {
                socket.emit('typing', {
                    receiver: otherUser,
                    typing: false
                });
            }, 1000);
        });

        socket.on('user_typing', function(data) {
            const typingIndicator = document.getElementById('typingIndicator');
            if (data.sender === otherUser) {
                typingIndicator.style.display = data.typing ? 'block' : 'none';
            }
        });

        // File upload
        document.getElementById('fileInput').addEventListener('change', function(e) {
            const file = e.target.files[0];
            if (file && file.type.startsWith('image/')) {
                const reader = new FileReader();
                reader.onload = function(e) {
                    const messageData = {
                        receiver: otherUser,
                        message: 'Shared an image',
                        type: 'image',
                        content: e.target.result
                    };
                    
                    if (replyingTo) {
                        messageData.reply_to = replyingTo;
                    }
                    
                    socket.emit('private_message', messageData);
                    cancelReply();
                };
                reader.readAsDataURL(file);
            }
        });

        // Event listeners
        document.getElementById('sendMessage').addEventListener('click', sendMessage);
        document.getElementById('messageInput').addEventListener('keypress', function(e) {
            if (e.key === 'Enter') {
                sendMessage();
            }
        });
        document.getElementById('cancelReply').addEventListener('click', cancelReply);

        // Attach actions to existing messages
        document.querySelectorAll('.message').forEach(messageElement => {
            const messageId = messageElement.getAttribute('data-message-id');
            const messageData = {{ messages|tojson }}.find(m => m.id == messageId);
            if (messageData) {
                attachMessageActions(messageElement, messageData);
            }
        });

        // Initial scroll
        scrollToBottom();

        // Initialize dark mode
        document.addEventListener('DOMContentLoaded', initializeDarkMode);
    </script>
</body>
</html>
"""

# Updated GROUP_CHAT_HTML with message actions and dark mode
GROUP_CHAT_HTML = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>{{ group.name }} - GEx</title>
    <script src="https://cdn.tailwindcss.com"></script>
    <script src="https://cdnjs.cloudflare.com/ajax/libs/socket.io/4.0.1/socket.io.js"></script>
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css">
    <style>
        :root {
            --bg-primary: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            --bg-secondary: white;
            --text-primary: #374151;
            --text-secondary: #6b7280;
            --border-color: #e5e7eb;
        }

        .dark-mode {
            --bg-primary: linear-gradient(135deg, #1e3a8a 0%, #581c87 100%);
            --bg-secondary: #1f2937;
            --text-primary: #f9fafb;
            --text-secondary: #d1d5db;
            --border-color: #374151;
        }

        body {
            background: var(--bg-primary);
            min-height: 100vh;
            color: var(--text-primary);
            transition: all 0.3s ease;
        }

        .bg-white {
            background-color: var(--bg-secondary) !important;
        }

        .text-gray-800, .text-gray-700, .text-gray-600, .text-gray-500 {
            color: var(--text-primary) !important;
        }

        .border-gray-200, .border-gray-300 {
            border-color: var(--border-color) !important;
        }

        .chat-container {
            height: calc(100vh - 200px);
        }
        .messages-container {
            height: calc(100% - 80px);
        }
        .message-self {
            background-color: #e9d5ff;
            margin-left: auto;
            max-width: 70%;
            position: relative;
        }
        .message-other {
            background-color: #f3f4f6;
            max-width: 70%;
            position: relative;
        }
        .dark-mode .message-other {
            background-color: #374151;
        }
        .message-actions {
            display: none;
            position: absolute;
            top: -40px;
            right: 0;
            background: var(--bg-secondary);
            border: 1px solid var(--border-color);
            border-radius: 8px;
            box-shadow: 0 4px 12px rgba(0,0,0,0.15);
            z-index: 100;
        }
        .message:hover .message-actions {
            display: flex;
        }
        .action-btn {
            padding: 8px 12px;
            border: none;
            background: none;
            cursor: pointer;
            color: var(--text-primary);
            transition: background-color 0.2s;
        }
        .action-btn:hover {
            background-color: var(--border-color);
        }
        .dark-mode .bg-orange-50 {
            background-color: #7c2d12 !important;
        }
        .dark-mode .bg-orange-100 {
            background-color: #9a3412 !important;
        }
        .dark-mode .text-orange-800 {
            color: #fdba74 !important;
        }
        .reply-indicator {
            background: var(--border-color);
            padding: 8px;
            border-radius: 8px;
            margin-bottom: 8px;
            font-size: 0.9em;
            border-left: 3px solid #f97316;
        }
    </style>
</head>
<body class="min-h-screen">
    <div class="max-w-6xl mx-auto px-4 py-6">
        <header class="bg-white rounded-2xl shadow-md p-6 mb-6 flex justify-between items-center">
            <div class="flex items-center">
                <a href="/groups" class="mr-4 px-3 py-2 rounded-lg bg-orange-100 text-orange-700 hover:bg-orange-200 transition">
                    <i class="fas fa-arrow-left"></i>
                </a>
                <div class="flex items-center">
                    {% if group.logo %}
                    <img src="{{ group.logo }}" class="w-12 h-12 rounded-full mr-3">
                    {% else %}
                    <div class="w-12 h-12 rounded-full bg-orange-100 flex items-center justify-center mr-3">
                        <i class="fas fa-users text-orange-600"></i>
                    </div>
                    {% endif %}
                    <div>
                        <h1 class="text-2xl font-bold text-orange-800">{{ group.name }}</h1>
                        <p class="text-orange-700">{{ group.members|length }} members</p>
                    </div>
                </div>
            </div>
            <div class="flex gap-3">
                <button id="darkModeToggle" class="px-4 py-2 rounded-xl bg-orange-100 text-orange-700 hover:bg-orange-200 transition">
                    <i id="darkModeIcon" class="fas fa-moon mr-2"></i>Theme
                </button>
                <a href="/" class="px-4 py-2 rounded-xl bg-orange-100 text-orange-700 hover:bg-orange-200 transition">
                    <i class="fas fa-home mr-2"></i>Home
                </a>
            </div>
        </header>

        <div class="bg-white rounded-2xl shadow-md chat-container flex flex-col">
            <!-- Group Info -->
            <div class="p-4 border-b bg-orange-50">
                <div class="flex justify-between items-center">
                    <div>
                        <h3 class="font-semibold text-orange-800">Group Description</h3>
                        <p class="text-sm text-orange-600">{{ group.description }}</p>
                    </div>
                    <div class="text-sm text-orange-600">
                        {{ group.members|length }} members • Created by {{ group.creator }}
                    </div>
                </div>
            </div>

            <!-- Messages -->
            <div id="messagesContainer" class="messages-container p-4 space-y-3 overflow-y-auto">
                {% for message in group.messages %}
                <div class="flex {{ 'justify-end' if message.sender == username else 'justify-start' }} message" data-message-id="{{ message.id }}">
                    <div class="max-w-xs md:max-w-md rounded-lg p-3 {{ 'message-self' if message.sender == username else 'message-other' }}">
                        {% if message.reply_to %}
                        <div class="reply-indicator text-sm text-gray-600 mb-2">
                            <i class="fas fa-reply mr-1"></i>
                            Replying to {{ message.reply_to.sender }}: {{ message.reply_to.message|truncate(30) }}
                        </div>
                        {% endif %}
                        
                        <div class="text-sm font-semibold text-gray-700 mb-1">{{ message.sender }}</div>
                        
                        {% if message.deleted %}
                        <div class="text-gray-500 italic">This message was deleted</div>
                        {% else %}
                            {% if message.type == 'text' %}
                            <div class="text-gray-800 message-content">{{ message.message }}</div>
                            {% elif message.type == 'image' %}
                            <img src="{{ message.content }}" class="max-w-full rounded" alt="Shared image">
                            {% endif %}
                        {% endif %}
                        
                        <div class="text-xs text-gray-500 mt-1">
                            {{ message.timestamp[11:16] }}
                            {% if message.edited %}
                            <span class="italic">(edited)</span>
                            {% endif %}
                        </div>
                        
                        <!-- Message Actions -->
                        {% if message.sender == username and not message.deleted %}
                        <div class="message-actions">
                            <button class="action-btn copy-btn" title="Copy">
                                <i class="fas fa-copy"></i>
                            </button>
                            <button class="action-btn edit-btn" title="Edit">
                                <i class="fas fa-edit"></i>
                            </button>
                            <button class="action-btn delete-btn" title="Delete">
                                <i class="fas fa-trash"></i>
                            </button>
                            <button class="action-btn reply-btn" title="Reply">
                                <i class="fas fa-reply"></i>
                            </button>
                        </div>
                        {% elif not message.deleted %}
                        <div class="message-actions">
                            <button class="action-btn copy-btn" title="Copy">
                                <i class="fas fa-copy"></i>
                            </button>
                            <button class="action-btn reply-btn" title="Reply">
                                <i class="fas fa-reply"></i>
                            </button>
                        </div>
                        {% endif %}
                    </div>
                </div>
                {% endfor %}
            </div>

            <!-- Reply Indicator -->
            <div id="replyIndicator" class="hidden p-3 border-b bg-gray-50">
                <div class="flex justify-between items-center">
                    <div>
                        <span class="text-sm text-gray-600">Replying to:</span>
                        <span id="replyPreview" class="text-sm ml-2"></span>
                    </div>
                    <button id="cancelReply" class="text-gray-500 hover:text-gray-700">
                        <i class="fas fa-times"></i>
                    </button>
                </div>
            </div>

            <!-- Message Input -->
            <div class="p-4 border-t">
                <div class="flex gap-2">
                    <input type="text" id="messageInput" placeholder="Type your message to the group..." 
                        class="flex-1 p-3 border border-gray-300 rounded-lg focus:ring-2 focus:ring-orange-500 focus:border-orange-500">
                    
                    <!-- File Upload Button -->
                    <label for="fileInput" class="px-4 py-3 bg-gray-600 text-white rounded-lg hover:bg-gray-700 transition cursor-pointer">
                        <i class="fas fa-paperclip"></i>
                    </label>
                    <input type="file" id="fileInput" accept="image/*" class="hidden">
                    
                    <button id="sendMessage" class="px-4 py-3 bg-orange-600 text-white rounded-lg hover:bg-orange-700 transition">
                        <i class="fas fa-paper-plane"></i>
                    </button>
                </div>
            </div>
        </div>
    </div>

    <script>
        const socket = io();
        const currentUser = "{{ username }}";
        const groupId = {{ group.id }};
        
        let replyingTo = null;
        let editingMessageId = null;

        // Dark mode functionality
        function initializeDarkMode() {
            const darkModeToggle = document.getElementById('darkModeToggle');
            const darkModeIcon = document.getElementById('darkModeIcon');
            const isDarkMode = localStorage.getItem('darkMode') === 'true';
            
            if (isDarkMode) {
                document.body.classList.add('dark-mode');
                darkModeIcon.classList.replace('fa-moon', 'fa-sun');
            }
            
            darkModeToggle.addEventListener('click', () => {
                document.body.classList.toggle('dark-mode');
                const isNowDark = document.body.classList.contains('dark-mode');
                
                if (isNowDark) {
                    darkModeIcon.classList.replace('fa-moon', 'fa-sun');
                } else {
                    darkModeIcon.classList.replace('fa-sun', 'fa-moon');
                }
                
                localStorage.setItem('darkMode', isNowDark);
            });
        }

        // Join group room
        socket.emit('join_group_chat', {group_id: groupId});

        // Scroll to bottom of messages
        function scrollToBottom() {
            const container = document.getElementById('messagesContainer');
            container.scrollTop = container.scrollHeight;
        }

        // Send message
        function sendMessage() {
            const messageInput = document.getElementById('messageInput');
            const message = messageInput.value.trim();
            
            if (message) {
                const messageData = {
                    group_id: groupId,
                    message: message,
                    type: 'text'
                };
                
                if (replyingTo) {
                    messageData.reply_to = replyingTo;
                }
                
                if (editingMessageId) {
                    // Edit existing message
                    socket.emit('edit_group_message', {
                        group_id: groupId,
                        message_id: editingMessageId,
                        new_message: message
                    });
                    editingMessageId = null;
                } else {
                    // Send new message
                    socket.emit('group_message', messageData);
                }
                
                messageInput.value = '';
                cancelReply();
            }
        }

        // Handle incoming messages
        socket.on('new_group_message', function(data) {
            if (data.group_id === groupId) {
                addMessageToUI(data.message);
                scrollToBottom();
            }
        });

        // Handle message edits
        socket.on('message_edited', function(data) {
            if (data.group_id === groupId) {
                const messageElement = document.querySelector(`[data-message-id="${data.message_id}"]`);
                if (messageElement) {
                    const contentElement = messageElement.querySelector('.message-content');
                    if (contentElement) {
                        contentElement.textContent = data.new_message;
                    }
                    const timestampElement = messageElement.querySelector('.text-xs');
                    if (timestampElement && !timestampElement.innerHTML.includes('edited')) {
                        timestampElement.innerHTML += ' <span class="italic">(edited)</span>';
                    }
                }
            }
        });

        // Handle message deletion
        socket.on('message_deleted', function(data) {
            if (data.group_id === groupId) {
                const messageElement = document.querySelector(`[data-message-id="${data.message_id}"]`);
                if (messageElement) {
                    const contentElement = messageElement.querySelector('.message-content');
                    if (contentElement) {
                        contentElement.innerHTML = '<span class="italic text-gray-500">This message was deleted</span>';
                    }
                    // Hide action buttons for deleted messages
                    const actionButtons = messageElement.querySelector('.message-actions');
                    if (actionButtons) {
                        actionButtons.style.display = 'none';
                    }
                }
            }
        });

        // Add message to UI
        function addMessageToUI(messageData) {
            const messagesContainer = document.getElementById('messagesContainer');
            const messageDiv = document.createElement('div');
            messageDiv.className = `flex ${messageData.sender === currentUser ? 'justify-end' : 'justify-start'} message`;
            messageDiv.setAttribute('data-message-id', messageData.id);
            
            let messageContent = '';
            if (messageData.deleted) {
                messageContent = '<div class="text-gray-500 italic">This message was deleted</div>';
            } else if (messageData.type === 'text') {
                messageContent = `<div class="text-gray-800 message-content">${messageData.message}</div>`;
            } else if (messageData.type === 'image') {
                messageContent = `<img src="${messageData.content}" class="max-w-full rounded" alt="Shared image">`;
            }
            
            let replySection = '';
            if (messageData.reply_to) {
                replySection = `
                    <div class="reply-indicator text-sm text-gray-600 mb-2">
                        <i class="fas fa-reply mr-1"></i>
                        Replying to ${messageData.reply_to.sender}: ${messageData.reply_to.message ? messageData.reply_to.message.substring(0, 30) + (messageData.reply_to.message.length > 30 ? '...' : '') : 'Message'}
                    </div>
                `;
            }
            
            let actionButtons = '';
            if (messageData.sender === currentUser && !messageData.deleted) {
                actionButtons = `
                    <div class="message-actions">
                        <button class="action-btn copy-btn" title="Copy">
                            <i class="fas fa-copy"></i>
                        </button>
                        <button class="action-btn edit-btn" title="Edit">
                            <i class="fas fa-edit"></i>
                        </button>
                        <button class="action-btn delete-btn" title="Delete">
                            <i class="fas fa-trash"></i>
                        </button>
                        <button class="action-btn reply-btn" title="Reply">
                            <i class="fas fa-reply"></i>
                        </button>
                    </div>
                `;
            } else if (!messageData.deleted) {
                actionButtons = `
                    <div class="message-actions">
                        <button class="action-btn copy-btn" title="Copy">
                            <i class="fas fa-copy"></i>
                        </button>
                        <button class="action-btn reply-btn" title="Reply">
                            <i class="fas fa-reply"></i>
                        </button>
                    </div>
                `;
            }
            
            messageDiv.innerHTML = `
                <div class="max-w-xs md:max-w-md rounded-lg p-3 ${messageData.sender === currentUser ? 'message-self' : 'message-other'}">
                    ${replySection}
                    <div class="text-sm font-semibold text-gray-700 mb-1">${messageData.sender}</div>
                    ${messageContent}
                    <div class="text-xs text-gray-500 mt-1">
                        ${new Date(messageData.timestamp).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })}
                        ${messageData.edited ? '<span class="italic">(edited)</span>' : ''}
                    </div>
                    ${actionButtons}
                </div>
            `;
            
            messagesContainer.appendChild(messageDiv);
            attachMessageActions(messageDiv, messageData);
        }

        // Attach action handlers to message
        function attachMessageActions(messageElement, messageData) {
            // Copy button
            const copyBtn = messageElement.querySelector('.copy-btn');
            if (copyBtn) {
                copyBtn.addEventListener('click', () => {
                    if (!messageData.deleted) {
                        navigator.clipboard.writeText(messageData.message);
                        // Show copied feedback
                        const originalHTML = copyBtn.innerHTML;
                        copyBtn.innerHTML = '<i class="fas fa-check"></i>';
                        setTimeout(() => {
                            copyBtn.innerHTML = originalHTML;
                        }, 1000);
                    }
                });
            }

            // Edit button
            const editBtn = messageElement.querySelector('.edit-btn');
            if (editBtn) {
                editBtn.addEventListener('click', () => {
                    if (!messageData.deleted) {
                        editingMessageId = messageData.id;
                        document.getElementById('messageInput').value = messageData.message;
                        document.getElementById('messageInput').focus();
                    }
                });
            }

            // Delete button
            const deleteBtn = messageElement.querySelector('.delete-btn');
            if (deleteBtn) {
                deleteBtn.addEventListener('click', () => {
                    if (!messageData.deleted && confirm('Are you sure you want to delete this message?')) {
                        socket.emit('delete_group_message', {
                            group_id: groupId,
                            message_id: messageData.id
                        });
                    }
                });
            }

            // Reply button
            const replyBtn = messageElement.querySelector('.reply-btn');
            if (replyBtn) {
                replyBtn.addEventListener('click', () => {
                    if (!messageData.deleted) {
                        replyingTo = {
                            id: messageData.id,
                            message: messageData.message,
                            sender: messageData.sender
                        };
                        showReplyIndicator(messageData);
                    }
                });
            }
        }

        // Show reply indicator
        function showReplyIndicator(messageData) {
            const replyIndicator = document.getElementById('replyIndicator');
            const replyPreview = document.getElementById('replyPreview');
            
            replyPreview.textContent = `${messageData.sender}: ${messageData.message.substring(0, 50)}${messageData.message.length > 50 ? '...' : ''}`;
            replyIndicator.classList.remove('hidden');
            
            document.getElementById('messageInput').focus();
        }

        // Cancel reply
        function cancelReply() {
            replyingTo = null;
            editingMessageId = null;
            const replyIndicator = document.getElementById('replyIndicator');
            replyIndicator.classList.add('hidden');
        }

        // File upload
        document.getElementById('fileInput').addEventListener('change', function(e) {
            const file = e.target.files[0];
            if (file && file.type.startsWith('image/')) {
                const reader = new FileReader();
                reader.onload = function(e) {
                    const messageData = {
                        group_id: groupId,
                        message: 'Shared an image',
                        type: 'image',
                        content: e.target.result
                    };
                    
                    if (replyingTo) {
                        messageData.reply_to = replyingTo;
                    }
                    
                    socket.emit('group_message', messageData);
                    cancelReply();
                };
                reader.readAsDataURL(file);
            }
        });

        // Event listeners
        document.getElementById('sendMessage').addEventListener('click', sendMessage);
        document.getElementById('messageInput').addEventListener('keypress', function(e) {
            if (e.key === 'Enter') {
                sendMessage();
            }
        });
        document.getElementById('cancelReply').addEventListener('click', cancelReply);

        // Attach actions to existing messages
        document.querySelectorAll('.message').forEach(messageElement => {
            const messageId = messageElement.getAttribute('data-message-id');
            const messageData = {{ group.messages|tojson }}.find(m => m.id == messageId);
            if (messageData) {
                attachMessageActions(messageElement, messageData);
            }
        });

        // Initial scroll
        scrollToBottom();

        // Initialize dark mode
        document.addEventListener('DOMContentLoaded', initializeDarkMode);
    </script>
</body>
</html>
"""
PENDING_VERIFICATION_HTML = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Verification Pending - GEx</title>
    <script src="https://cdn.tailwindcss.com"></script>
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css">
    <style>
        body {
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            min-height: 100vh;
        }
    </style>
</head>
<body class="min-h-screen flex items-center justify-center">
    <div class="bg-white p-8 rounded-2xl shadow-md w-full max-w-md text-center">
        <div class="mb-6">
            <i class="fas fa-clock text-4xl text-yellow-500 mb-4"></i>
            <h1 class="text-2xl font-bold text-gray-800">Account Verification Pending</h1>
        </div>
        
        <p class="text-gray-600 mb-4">
            Hello <span class="font-semibold">{{ username }}</span>! Your account is pending verification by an administrator.
        </p>
        
        <p class="text-gray-600 mb-6">
            Please wait up to 1 hour for your account to be verified. You will be able to access all features once verified.
        </p>
        
        <div class="bg-yellow-50 border border-yellow-200 rounded-lg p-4 mb-6">
            <p class="text-yellow-800 text-sm">
                <i class="fas fa-info-circle mr-2"></i>
                You will be automatically redirected once your account is verified.
            </p>
        </div>
        
        <div class="flex justify-center space-x-4">
            <a href="/logout" class="bg-gray-600 text-white px-6 py-2 rounded-lg hover:bg-gray-700 transition">
                <i class="fas fa-sign-out-alt mr-2"></i>Logout
            </a>
        </div>
    </div>

    <script>
        // Check verification status every 30 seconds
        setInterval(() => {
            fetch('/')
                .then(response => {
                    if (response.redirected) {
                        window.location.href = '/';
                    }
                })
                .catch(error => console.error('Error checking verification:', error));
        }, 30000);
    </script>
</body>
</html>
"""

ADMIN_HTML = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Admin Panel - GEx</title>
    <script src="https://cdn.tailwindcss.com"></script>
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css">
    <style>
        body {
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            min-height: 100vh;
        }
    </style>
</head>
<body class="min-h-screen">
    <div class="max-w-6xl mx-auto px-4 py-6">
        <header class="bg-white rounded-2xl shadow-md p-6 mb-6 flex justify-between items-center">
            <div>
                <h1 class="text-3xl font-bold text-purple-800">Admin Panel - GEx</h1>
                <p class="text-purple-700">User Verification Management</p>
            </div>
            <a href="/" class="px-4 py-2 rounded-xl bg-purple-100 text-purple-700 hover:bg-purple-200 transition">
                <i class="fas fa-home mr-2"></i>Home
            </a>
        </header>

        <!-- Pending Verifications -->
        <section class="bg-white rounded-2xl shadow-md p-6 mb-6">
            <h2 class="text-2xl font-bold text-yellow-800 mb-4">Pending Verifications</h2>
            {% if pending_users %}
            <div class="overflow-x-auto">
                <table class="min-w-full text-sm">
                    <thead class="bg-gray-100">
                        <tr>
                            <th class="p-3 text-left">Username</th>
                            <th class="p-3 text-left">Team Name</th>
                            <th class="p-3 text-left">Joined Date</th>
                            <th class="p-3 text-center">Actions</th>
                        </tr>
                    </thead>
                    <tbody>
                        {% for username in pending_users %}
                        <tr class="border-b border-gray-200">
                            <td class="p-3 font-medium">{{ username }}</td>
                            <td class="p-3">{{ users[username].team_name }}</td>
                            <td class="p-3">{{ users[username].joined_at[:10] }}</td>
                            <td class="p-3 text-center">
                                <a href="/admin/verify/{{ username }}" 
                                   class="bg-green-600 text-white px-4 py-2 rounded-lg hover:bg-green-700 transition"
                                   onclick="return confirm('Verify {{ username }}?')">
                                    <i class="fas fa-check mr-2"></i>Verify
                                </a>
                            </td>
                        </tr>
                        {% endfor %}
                    </tbody>
                </table>
            </div>
            {% else %}
            <p class="text-gray-600 text-center py-4">No pending verifications.</p>
            {% endif %}
        </section>

        <!-- Verified Users -->
        <section class="bg-white rounded-2xl shadow-md p-6">
            <h2 class="text-2xl font-bold text-green-800 mb-4">Verified Users</h2>
            {% if verified_users %}
            <div class="overflow-x-auto">
                <table class="min-w-full text-sm">
                    <thead class="bg-gray-100">
                        <tr>
                            <th class="p-3 text-left">Username</th>
                            <th class="p-3 text-left">Team Name</th>
                            <th class="p-3 text-left">Joined Date</th>
                            <th class="p-3 text-center">Status</th>
                        </tr>
                    </thead>
                    <tbody>
                        {% for username in verified_users %}
                        <tr class="border-b border-gray-200">
                            <td class="p-3 font-medium">{{ username }}</td>
                            <td class="p-3">{{ users[username].team_name }}</td>
                            <td class="p-3">{{ users[username].joined_at[:10] }}</td>
                            <td class="p-3 text-center">
                                <span class="bg-green-100 text-green-800 px-3 py-1 rounded-full text-sm">
                                    <i class="fas fa-check-circle mr-1"></i>Verified
                                </span>
                            </td>
                        </tr>
                        {% endfor %}
                    </tbody>
                </table>
            </div>
            {% else %}
            <p class="text-gray-600 text-center py-4">No verified users yet.</p>
            {% endif %}
        </section>
    </div>
</body>
</html>
"""

LOGIN_HTML = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Login - GEx</title>
    <script src="https://cdn.tailwindcss.com"></script>
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css">
    <style>
        body {
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            min-height: 100vh;
        }
    </style>
</head>
<body class="min-h-screen flex items-center justify-center">
    <div class="bg-white p-8 rounded-2xl shadow-md w-full max-w-md">
        <h1 class="text-3xl font-bold text-purple-800 mb-6 text-center">GEx</h1>
        
        {% if error %}
        <div class="bg-red-100 border border-red-400 text-red-700 px-4 py-3 rounded mb-4">
            {{ error }}
        </div>
        {% endif %}
        
        <form method="POST">
            <div class="mb-4">
                <label for="username" class="block text-gray-700 text-sm font-bold mb-2">Username</label>
                <input type="text" id="username" name="username" required 
                    class="shadow appearance-none border rounded w-full py-2 px-3 text-gray-700 leading-tight focus:outline-none focus:shadow-outline">
            </div>
            
            <div class="mb-6">
                <label for="password" class="block text-gray-700 text-sm font-bold mb-2">Password</label>
                <input type="password" id="password" name="password" required 
                    class="shadow appearance-none border rounded w-full py-2 px-3 text-gray-700 mb-3 leading-tight focus:outline-none focus:shadow-outline">
            </div>
            
            <div class="flex items-center justify-between">
                <button type="submit" class="bg-purple-600 hover:bg-purple-700 text-white font-bold py-2 px-4 rounded focus:outline-none focus:shadow-outline w-full">
                    Sign In
                </button>
            </div>
        </form>
        
        <div class="mt-4 text-center">
            <a href="/register" class="text-purple-600 hover:text-purple-800 text-sm">
                Don't have an account? Register
            </a>
        </div>
    </div>
</body>
</html>
"""

REGISTER_HTML = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Register - GEx</title>
    <script src="https://cdn.tailwindcss.com"></script>
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css">
    <style>
        body {
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            min-height: 100vh;
        }
    </style>
</head>
<body class="min-h-screen flex items-center justify-center">
    <div class="bg-white p-8 rounded-2xl shadow-md w-full max-w-md">
        <h1 class="text-3xl font-bold text-purple-800 mb-6 text-center">GEx</h1>
        
        {% if error %}
        <div class="bg-red-100 border border-red-400 text-red-700 px-4 py-3 rounded mb-4">
            {{ error }}
        </div>
        {% endif %}
        
        <form method="POST" enctype="multipart/form-data">
            <div class="mb-4">
                <label for="username" class="block text-gray-700 text-sm font-bold mb-2">Username</label>
                <input type="text" id="username" name="username" placeholder = "USERNAME MUST BE YOUR TEAMNAME"required 
                    class="shadow appearance-none border rounded w-full py-2 px-3 text-gray-700 leading-tight focus:outline-none focus:shadow-outline">
            </div>
            
            <div class="mb-4">
                <label for="password" class="block text-gray-700 text-sm font-bold mb-2">Password</label>
                <input type="password" id="password" name="password" required 
                    class="shadow appearance-none border rounded w-full py-2 px-3 text-gray-700 leading-tight focus:outline-none focus:shadow-outline">
            </div>
            
            <div class="mb-4">
                <label for="confirm_password" class="block text-gray-700 text-sm font-bold mb-2">Confirm Password</label>
                <input type="password" id="confirm_password" name="confirm_password" required 
                    class="shadow appearance-none border rounded w-full py-2 px-3 text-gray-700 leading-tight focus:outline-none focus:shadow-outline">
            </div>

            <div class="mb-4">
                <label for="team_name" class="block text-gray-700 text-sm font-bold mb-2">Team Name</label>
                <input type="text" id="team_name" name="team_name" 
                    class="shadow appearance-none border rounded w-full py-2 px-3 text-gray-700 leading-tight focus:outline-none focus:shadow-outline"
                    placeholder="Your team name">
            </div>

            <div class="mb-6">
                <label for="team_logo" class="block text-gray-700 text-sm font-bold mb-2">Team Logo</label>
                <input type="file" id="team_logo" name="team_logo" accept="image/*" 
                    class="shadow appearance-none border rounded w-full py-2 px-3 text-gray-700 leading-tight focus:outline-none focus:shadow-outline">
            </div>
            
            <div class="flex items-center justify-between">
                <button type="submit" class="bg-purple-600 hover:bg-purple-700 text-white font-bold py-2 px-4 rounded focus:outline-none focus:shadow-outline w-full">
                    Register
                </button>
            </div>
        </form>
        
        <div class="mt-4 text-center">
            <a href="/login" class="text-purple-600 hover:text-purple-800 text-sm">
                Already have an account? Sign in
            </a>
        </div>
    </div>
</body>
</html>
"""
PROFILE_HTML = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Profile - GEx</title>
    <script src="https://cdn.tailwindcss.com"></script>
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css">
    <style>
        body {
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            min-height: 100vh;
        }
        .profile-picture {
            width: 150px;
            height: 150px;
            border: 4px solid white;
            box-shadow: 0 4px 12px rgba(0,0,0,0.15);
        }
        @media (max-width: 768px) {
            .profile-picture {
                width: 120px;
                height: 120px;
            }
        }
    </style>
</head>
<body class="min-h-screen">
    <div class="max-w-2xl mx-auto px-4 py-6">
        <header class="bg-white rounded-2xl shadow-md p-6 mb-6 flex justify-between items-center">
            <div>
                <h1 class="text-3xl font-bold text-purple-800">Profile</h1>
                <p class="text-purple-700">Manage your profile settings</p>
            </div>
            <a href="/" class="px-4 py-2 rounded-xl bg-purple-100 text-purple-700 hover:bg-purple-200 transition">
                <i class="fas fa-arrow-left mr-2"></i>Back
            </a>
        </header>

        <div class="bg-white rounded-2xl shadow-md p-6">
            <form method="POST" enctype="multipart/form-data">
                <!-- Profile Picture -->
                <div class="text-center mb-6">
                    <div class="relative inline-block">
                        {% if user.profile_picture %}
                        <img id="profilePreview" src="{{ user.profile_picture }}" class="profile-picture rounded-full mx-auto">
                        {% else %}
                        <div id="profilePreview" class="profile-picture rounded-full mx-auto bg-purple-100 flex items-center justify-center">
                            <i class="fas fa-user text-purple-600 text-4xl"></i>
                        </div>
                        {% endif %}
                        <label for="profile_picture" class="absolute bottom-2 right-2 bg-purple-600 text-white p-2 rounded-full cursor-pointer hover:bg-purple-700 transition">
                            <i class="fas fa-camera"></i>
                        </label>
                    </div>
                    <input type="file" id="profile_picture" name="profile_picture" accept="image/*" class="hidden" onchange="previewProfilePicture(this)">
                    <p class="text-sm text-gray-600 mt-2">Click camera icon to change profile picture</p>
                </div>

                <!-- User Info -->
                <div class="grid grid-cols-1 md:grid-cols-2 gap-4 mb-4">
                    <div>
                        <label class="block text-gray-700 text-sm font-bold mb-2">Username</label>
                        <input type="text" value="{{ username }}" class="w-full p-3 border border-gray-300 rounded-lg bg-gray-100" readonly>
                    </div>
                    <div>
                        <label class="block text-gray-700 text-sm font-bold mb-2">Team Name</label>
                        <input type="text" value="{{ user.team_name }}" class="w-full p-3 border border-gray-300 rounded-lg bg-gray-100" readonly>
                    </div>
                </div>

                <!-- About Section -->
                <div class="mb-6">
                    <label for="about" class="block text-gray-700 text-sm font-bold mb-2">About</label>
                    <textarea id="about" name="about" rows="4" 
                        class="w-full p-3 border border-gray-300 rounded-lg focus:ring-2 focus:ring-purple-500 focus:border-purple-500"
                        placeholder="Tell others about yourself...">{{ user.about or '' }}</textarea>
                </div>

                <!-- Stats -->
                <div class="bg-gray-50 rounded-lg p-4 mb-6">
                    <h3 class="text-lg font-semibold text-gray-800 mb-3">Your Stats</h3>
                    <div class="grid grid-cols-2 md:grid-cols-4 gap-4 text-center">
                        <div>
                            <p class="text-2xl font-bold text-purple-700">{{ user_leagues|length }}</p>
                            <p class="text-sm text-gray-600">Leagues</p>
                        </div>
                        <div>
                            <p class="text-2xl font-bold text-orange-700">{{ user_groups|length }}</p>
                            <p class="text-sm text-gray-600">Groups</p>
                        </div>
                        <div>
                            <p class="text-2xl font-bold text-blue-700">{{ status_posts|length }}</p>
                            <p class="text-sm text-gray-600">Posts</p>
                        </div>
                        <div>
                            <p class="text-2xl font-bold text-green-700">{{ user.joined_at[:10] }}</p>
                            <p class="text-sm text-gray-600">Joined</p>
                        </div>
                    </div>
                </div>

                <div class="flex justify-center">
                    <button type="submit" class="bg-purple-600 hover:bg-purple-700 text-white font-bold py-3 px-8 rounded-lg focus:outline-none focus:shadow-outline transition">
                        <i class="fas fa-save mr-2"></i>Save Changes
                    </button>
                </div>
            </form>
        </div>
    </div>

    <script>
        function previewProfilePicture(input) {
            const preview = document.getElementById('profilePreview');
            if (input.files && input.files[0]) {
                const reader = new FileReader();
                reader.onload = function(e) {
                    if (preview.tagName === 'IMG') {
                        preview.src = e.target.result;
                    } else {
                        // Convert div to img
                        const newPreview = document.createElement('img');
                        newPreview.id = 'profilePreview';
                        newPreview.className = 'profile-picture rounded-full mx-auto';
                        newPreview.src = e.target.result;
                        preview.parentNode.replaceChild(newPreview, preview);
                    }
                }
                reader.readAsDataURL(input.files[0]);
            }
        }
    </script>
</body>
</html>
"""
GROUPS_HTML = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Groups - GEx</title>
    <script src="https://cdn.tailwindcss.com"></script>
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css">
    <style>
        body {
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            min-height: 100vh;
        }
        .groups-container {
            max-height: calc(100vh - 200px);
            overflow-y: auto;
        }
        .group-item {
            transition: all 0.2s ease;
            border-bottom: 1px solid #e5e7eb;
        }
        .group-item:hover {
            background-color: #f8fafc;
        }
        .group-item:last-child {
            border-bottom: none;
        }
        .online-dot {
            width: 8px;
            height: 8px;
            background: #10B981;
            border-radius: 50%;
            display: inline-block;
        }
        .unread-badge {
            background: #EF4444;
            color: white;
            border-radius: 50%;
            width: 20px;
            height: 20px;
            display: flex;
            align-items: center;
            justify-content: center;
            font-size: 12px;
        }
    </style>
</head>
<body class="min-h-screen">
    <div class="max-w-4xl mx-auto px-4 py-6">
        <header class="bg-white rounded-2xl shadow-md p-6 mb-6">
            <div class="flex justify-between items-center">
                <div>
                    <h1 class="text-3xl font-bold text-purple-800">Groups</h1>
                    <p class="text-purple-700">Join group chats with other players</p>
                </div>
                <div class="flex gap-3">
                    <a href="/create_group" class="px-4 py-2 rounded-xl bg-green-600 text-white hover:bg-green-700 transition">
                        <i class="fas fa-plus mr-2"></i>Create Group
                    </a>
                    <a href="/" class="px-4 py-2 rounded-xl bg-purple-100 text-purple-700 hover:bg-purple-200 transition">
                        <i class="fas fa-home mr-2"></i>Home
                    </a>
                </div>
            </div>
        </header>

        <div class="bg-white rounded-2xl shadow-md overflow-hidden">
            <!-- Groups Header -->
            <div class="p-4 border-b border-gray-200 bg-gray-50">
                <div class="flex justify-between items-center">
                    <h2 class="text-lg font-semibold text-gray-800">All Groups</h2>
                    <span class="text-sm text-gray-500">{{ (user_groups + available_groups)|length }} groups</span>
                </div>
            </div>

            <!-- Groups List -->
            <div class="groups-container">
                <!-- Your Groups Section -->
                {% if user_groups %}
                <div class="p-3 bg-blue-50 border-b border-blue-100">
                    <h3 class="text-sm font-semibold text-blue-800 flex items-center">
                        <i class="fas fa-users mr-2"></i>
                        Your Groups ({{ user_groups|length }})
                    </h3>
                </div>
                {% for group in user_groups %}
                <div class="group-item p-4 flex items-center justify-between hover:bg-gray-50 cursor-pointer">
                    <div class="flex items-center space-x-4 flex-1 min-w-0">
                        <div class="relative flex-shrink-0">
                            {% if group.logo %}
                            <img src="{{ group.logo }}" class="w-12 h-12 rounded-full">
                            {% else %}
                            <div class="w-12 h-12 rounded-full bg-orange-100 flex items-center justify-center">
                                <i class="fas fa-users text-orange-600"></i>
                            </div>
                            {% endif %}
                            <span class="online-dot absolute bottom-0 right-0 border-2 border-white"></span>
                        </div>
                        <div class="flex-1 min-w-0">
                            <div class="flex items-center justify-between">
                                <h3 class="font-semibold text-gray-800 truncate">{{ group.name }}</h3>
                                <span class="text-xs text-gray-500 ml-2 flex-shrink-0">
                                    {{ group.created_at[:10] }}
                                </span>
                            </div>
                            <p class="text-sm text-gray-600 truncate mb-1">{{ group.description or "No description" }}</p>
                            <div class="flex items-center text-xs text-gray-500">
                                <span class="flex items-center mr-3">
                                    <i class="fas fa-user-friends mr-1"></i>
                                    {{ group.members|length }} members
                                </span>
                                <span class="flex items-center">
                                    <i class="fas fa-crown mr-1 text-yellow-500"></i>
                                    {{ group.creator }}
                                </span>
                            </div>
                        </div>
                    </div>
                    <div class="flex items-center space-x-2 ml-4 flex-shrink-0">
                        <a href="/group/{{ group.id }}" class="bg-orange-600 text-white px-4 py-2 rounded-lg hover:bg-orange-700 transition text-sm">
                            Open
                        </a>
                        <a href="/leave_group/{{ group.id }}" class="bg-red-600 text-white p-2 rounded-lg hover:bg-red-700 transition text-sm" 
                           onclick="return confirm('Leave {{ group.name }}?')" title="Leave Group">
                            <i class="fas fa-sign-out-alt"></i>
                        </a>
                    </div>
                </div>
                {% endfor %}
                {% endif %}

                <!-- Available Groups Section -->
                {% if available_groups %}
                <div class="p-3 bg-green-50 border-b border-green-100">
                    <h3 class="text-sm font-semibold text-green-800 flex items-center">
                        <i class="fas fa-user-plus mr-2"></i>
                        Available Groups ({{ available_groups|length }})
                    </h3>
                </div>
                {% for group in available_groups %}
                <div class="group-item p-4 flex items-center justify-between hover:bg-gray-50 cursor-pointer">
                    <div class="flex items-center space-x-4 flex-1 min-w-0">
                        <div class="relative flex-shrink-0">
                            {% if group.logo %}
                            <img src="{{ group.logo }}" class="w-12 h-12 rounded-full">
                            {% else %}
                            <div class="w-12 h-12 rounded-full bg-green-100 flex items-center justify-center">
                                <i class="fas fa-users text-green-600"></i>
                            </div>
                            {% endif %}
                            <span class="online-dot absolute bottom-0 right-0 border-2 border-white"></span>
                        </div>
                        <div class="flex-1 min-w-0">
                            <div class="flex items-center justify-between">
                                <h3 class="font-semibold text-gray-800 truncate">{{ group.name }}</h3>
                                <span class="text-xs text-gray-500 ml-2 flex-shrink-0">
                                    {{ group.created_at[:10] }}
                                </span>
                            </div>
                            <p class="text-sm text-gray-600 truncate mb-1">{{ group.description or "No description" }}</p>
                            <div class="flex items-center text-xs text-gray-500">
                                <span class="flex items-center mr-3">
                                    <i class="fas fa-user-friends mr-1"></i>
                                    {{ group.members|length }} members
                                </span>
                                <span class="flex items-center">
                                    <i class="fas fa-crown mr-1 text-yellow-500"></i>
                                    {{ group.creator }}
                                </span>
                            </div>
                        </div>
                    </div>
                    <div class="ml-4 flex-shrink-0">
                        <a href="/join_group/{{ group.id }}" class="bg-green-600 text-white px-4 py-2 rounded-lg hover:bg-green-700 transition text-sm">
                            Join
                        </a>
                    </div>
                </div>
                {% endfor %}
                {% endif %}

                <!-- Empty State -->
                {% if not user_groups and not available_groups %}
                <div class="text-center py-12">
                    <div class="w-24 h-24 mx-auto mb-4 rounded-full bg-gray-100 flex items-center justify-center">
                        <i class="fas fa-users text-gray-400 text-3xl"></i>
                    </div>
                    <h3 class="text-lg font-semibold text-gray-600 mb-2">No Groups Available</h3>
                    <p class="text-gray-500 mb-6">Create the first group to start chatting with others!</p>
                    <a href="/create_group" class="bg-purple-600 text-white px-6 py-3 rounded-lg hover:bg-purple-700 transition">
                        <i class="fas fa-plus mr-2"></i>Create Your First Group
                    </a>
                </div>
                {% endif %}
            </div>

            <!-- Footer Stats -->
            <div class="p-4 border-t border-gray-200 bg-gray-50">
                <div class="flex justify-between items-center text-sm text-gray-600">
                    <div class="flex items-center space-x-4">
                        <span class="flex items-center">
                            <i class="fas fa-users text-blue-500 mr-1"></i>
                            Your Groups: {{ user_groups|length }}
                        </span>
                        <span class="flex items-center">
                            <i class="fas fa-user-plus text-green-500 mr-1"></i>
                            Available: {{ available_groups|length }}
                        </span>
                    </div>
                    <div class="text-xs text-gray-500">
                        Total: {{ (user_groups + available_groups)|length }} groups
                    </div>
                </div>
            </div>
        </div>
    </div>

    <script>
        // Add smooth hover effects
        document.addEventListener('DOMContentLoaded', function() {
            const groupItems = document.querySelectorAll('.group-item');
            
            groupItems.forEach(item => {
                item.addEventListener('click', function(e) {
                    // If click is not on a button, open the group
                    if (!e.target.closest('a')) {
                        const openLink = this.querySelector('a[href*="/group/"], a[href*="/join_group/"]');
                        if (openLink) {
                            openLink.click();
                        }
                    }
                });
            });
        });
    </script>
</body>
</html>
"""
CREATE_GROUP_HTML = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Create Group - FC League Manager</title>
    <script src="https://cdn.tailwindcss.com"></script>
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css">
    <style>
        body {
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            min-height: 100vh;
        }
    </style>
</head>
<body class="min-h-screen">
    <div class="max-w-2xl mx-auto px-4 py-6">
        <header class="bg-white rounded-2xl shadow-md p-6 mb-6 flex justify-between items-center">
            <div>
                <h1 class="text-3xl font-bold text-purple-800">Create New Group</h1>
                <p class="text-purple-700">Start a group chat with other players</p>
            </div>
            <a href="/groups" class="px-4 py-2 rounded-xl bg-purple-100 text-purple-700 hover:bg-purple-200 transition">
                <i class="fas fa-arrow-left mr-2"></i>Back
            </a>
        </header>

        <div class="bg-white rounded-2xl shadow-md p-6">
            {% if error %}
            <div class="bg-red-100 border border-red-400 text-red-700 px-4 py-3 rounded mb-4">
                {{ error }}
            </div>
            {% endif %}
            
            <form method="POST" enctype="multipart/form-data">
                <div class="mb-4">
                    <label for="name" class="block text-gray-700 text-sm font-bold mb-2">Group Name</label>
                    <input type="text" id="name" name="name" required 
                        class="shadow appearance-none border rounded w-full py-2 px-3 text-gray-700 leading-tight focus:outline-none focus:shadow-outline">
                </div>
                
                <div class="mb-4">
                    <label for="description" class="block text-gray-700 text-sm font-bold mb-2">Description</label>
                    <textarea id="description" name="description" rows="3" 
                        class="shadow appearance-none border rounded w-full py-2 px-3 text-gray-700 leading-tight focus:outline-none focus:shadow-outline"
                        placeholder="What is this group about?"></textarea>
                </div>
                
                <div class="mb-6">
                    <label for="logo" class="block text-gray-700 text-sm font-bold mb-2">Group Logo</label>
                    <input type="file" id="logo" name="logo" accept="image/*" 
                        class="shadow appearance-none border rounded w-full py-2 px-3 text-gray-700 leading-tight focus:outline-none focus:shadow-outline">
                </div>
                
                <div class="flex items-center justify-between">
                    <button type="submit" class="bg-purple-600 hover:bg-purple-700 text-white font-bold py-2 px-4 rounded focus:outline-none focus:shadow-outline w-full">
                        Create Group
                    </button>
                </div>
            </form>
        </div>
    </div>
</body>
</html>
"""

STATUS_FEED_HTML = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Updates - GEx</title>
    <script src="https://cdn.tailwindcss.com"></script>
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css">
    <style>
        body {
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            min-height: 100vh;
        }
        .bottom-nav {
            position: fixed;
            bottom: 0;
            left: 0;
            right: 0;
            background: rgba(255, 255, 255, 0.95);
            backdrop-filter: blur(10px);
            border-top: 1px solid rgba(0, 0, 0, 0.1);
        }
        .upload-modal {
            display: none;
            position: fixed;
            top: 0;
            left: 0;
            width: 100%;
            height: 100%;
            background: rgba(0, 0, 0, 0.9);
            z-index: 1000;
            align-items: center;
            justify-content: center;
        }
        .plus-btn {
            width: 60px;
            height: 60px;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            border-radius: 50%;
            display: flex;
            align-items: center;
            justify-content: center;
            margin-top: -30px;
            box-shadow: 0 4px 15px rgba(0, 0, 0, 0.2);
            transition: all 0.3s ease;
        }
        .plus-btn:hover {
            transform: scale(1.1);
        }
        .nav-btn {
            transition: all 0.3s ease;
        }
        .nav-btn.active {
            color: #667eea;
            transform: translateY(-2px);
        }
        .preview-media {
            max-width: 90%;
            max-height: 60vh;
            border-radius: 12px;
        }
    </style>
</head>
<body class="min-h-screen pb-20">
    <div class="max-w-2xl mx-auto px-4 py-6">
        <header class="bg-white rounded-2xl shadow-md p-6 mb-6">
            <div class="text-center">
                <h1 class="text-3xl font-bold text-purple-800">Status Feed</h1>
                <p class="text-purple-700">See what everyone is up to</p>
            </div>
        </header>

        <!-- Upload Modal -->
        <div id="uploadModal" class="upload-modal">
            <div class="bg-white rounded-2xl p-6 m-4 max-w-md w-full">
                <h2 class="text-xl font-semibold mb-4 text-center">Create New Post</h2>
                
                <!-- Preview Area -->
                <div id="mediaPreview" class="mb-4 text-center hidden">
                    <img id="imagePreview" class="preview-media hidden">
                    <video id="videoPreview" class="preview-media hidden" controls></video>
                </div>
                
                <form id="uploadForm" method="POST" enctype="multipart/form-data">
                    <div class="mb-4">
                        <textarea name="content" id="postContent" rows="4" 
                            class="w-full p-3 border border-gray-300 rounded-lg focus:ring-2 focus:ring-blue-500 focus:border-blue-500"
                            placeholder="What's on your mind?"></textarea>
                    </div>
                    
                    <div class="flex space-x-3 mb-4">
                        <label class="flex-1 bg-blue-600 text-white px-4 py-3 rounded-lg hover:bg-blue-700 transition cursor-pointer text-center">
                            <i class="fas fa-camera mr-2"></i>Add Media
                            <input type="file" name="media" id="mediaInput" accept="image/*,video/*" class="hidden" onchange="previewMedia(this)">
                        </label>
                    </div>
                    
                    <div class="flex space-x-3">
                        <button type="button" onclick="closeUploadModal()" class="flex-1 bg-gray-500 text-white px-4 py-3 rounded-lg hover:bg-gray-600 transition">
                            Cancel
                        </button>
                        <button type="submit" class="flex-1 bg-purple-600 text-white px-4 py-3 rounded-lg hover:bg-purple-700 transition">
                            <i class="fas fa-paper-plane mr-2"></i>Post
                        </button>
                    </div>
                </form>
            </div>
        </div>

        <!-- Status Posts -->
        <div class="space-y-6">
            {% for post in status_posts %}
            <div class="bg-white rounded-2xl shadow-md p-6">
                <!-- Post Header -->
                <div class="flex items-center mb-4">
                    {% if users[post.username].profile_picture %}
                    <img src="{{ users[post.username].profile_picture }}" class="w-12 h-12 rounded-full mr-3">
                    {% else %}
                    <div class="w-12 h-12 rounded-full bg-purple-100 flex items-center justify-center mr-3">
                        <i class="fas fa-user text-purple-600"></i>
                    </div>
                    {% endif %}
                    <div>
                        <h3 class="font-semibold text-gray-800">{{ post.username }}</h3>
                        <p class="text-sm text-gray-500">{{ post.timestamp[:16].replace('T', ' ') }}</p>
                    </div>
                </div>

                <!-- Post Content -->
                <div class="mb-4">
                    <p class="text-gray-800">{{ post.content }}</p>
                </div>

                <!-- Media -->
                {% if post.media_type == 'image' and post.media_content %}
                <div class="mb-4">
                    <img src="{{ post.media_content }}" class="w-full rounded-lg">
                </div>
                {% elif post.media_type == 'video' and post.media_content %}
                <div class="mb-4">
                    <video controls class="w-full rounded-lg">
                        <source src="{{ post.media_content }}" type="video/mp4">
                    </video>
                </div>
                {% endif %}

                <!-- Post Actions -->
                <div class="flex justify-between items-center border-t border-gray-200 pt-4">
                    <div class="flex space-x-4">
                        <button onclick="likeStatus({{ post.id }})" class="flex items-center space-x-1 text-gray-600 hover:text-red-600 transition">
                            <i class="fas fa-heart {{ 'text-red-600' if username in post.likes else '' }}"></i>
                            <span>{{ post.likes|length }}</span>
                        </button>
                        <button onclick="toggleComments({{ post.id }})" class="flex items-center space-x-1 text-gray-600 hover:text-blue-600 transition">
                            <i class="fas fa-comment"></i>
                            <span>{{ post.comments|length }}</span>
                        </button>
                    </div>
                </div>

                <!-- Comments Section -->
                <div id="comments-{{ post.id }}" class="mt-4 hidden">
                    <div class="space-y-3">
                        {% for comment in post.comments %}
                        <div class="flex items-start space-x-3">
                            <div class="w-8 h-8 rounded-full bg-gray-200 flex items-center justify-center flex-shrink-0">
                                <i class="fas fa-user text-gray-500 text-sm"></i>
                            </div>
                            <div class="flex-1">
                                <div class="bg-gray-100 rounded-lg p-3">
                                    <p class="font-semibold text-sm">{{ comment.username }}</p>
                                    <p class="text-gray-800">{{ comment.comment }}</p>
                                </div>
                                <p class="text-xs text-gray-500 mt-1">{{ comment.timestamp[:16].replace('T', ' ') }}</p>
                            </div>
                        </div>
                        {% endfor %}
                    </div>
                    <div class="mt-3 flex space-x-2">
                        <input type="text" id="comment-{{ post.id }}" 
                            class="flex-1 p-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-blue-500 focus:border-blue-500"
                            placeholder="Write a comment...">
                        <button onclick="addComment({{ post.id }})" class="bg-blue-600 text-white px-4 py-2 rounded-lg hover:bg-blue-700 transition">
                            Post
                        </button>
                    </div>
                </div>
            </div>
            {% endfor %}
        </div>
    </div>

    <!-- Bottom Navigation -->
    <div class="bottom-nav">
        <div class="max-w-2xl mx-auto px-4 py-3">
            <div class="flex justify-between items-center">
                <!-- Home Button -->
                <a href="/" class="nav-btn flex flex-col items-center text-gray-600 hover:text-purple-600">
                    <i class="fas fa-home text-xl mb-1"></i>
                    <span class="text-xs">Home</span>
                </a>

                <!-- Search Button -->
                <button class="nav-btn flex flex-col items-center text-gray-600 hover:text-purple-600">
                    <i class="fas fa-search text-xl mb-1"></i>
                    <span class="text-xs">Search</span>
                </button>

                <!-- Central Plus Button -->
                <div class="relative">
                    <button onclick="openUploadModal()" class="plus-btn text-white">
                        <i class="fas fa-plus text-2xl"></i>
                    </button>
                </div>

                <!-- Notifications Button -->
                <button class="nav-btn flex flex-col items-center text-gray-600 hover:text-purple-600">
                    <i class="fas fa-bell text-xl mb-1"></i>
                    <span class="text-xs">Alerts</span>
                </button>

                <!-- Profile Button -->
                <a href="/profile" class="nav-btn flex flex-col items-center text-gray-600 hover:text-purple-600">
                    <i class="fas fa-user text-xl mb-1"></i>
                    <span class="text-xs">Profile</span>
                </a>
            </div>
        </div>
    </div>

    <script>
        function openUploadModal() {
            document.getElementById('uploadModal').style.display = 'flex';
            document.body.style.overflow = 'hidden';
        }

        function closeUploadModal() {
            document.getElementById('uploadModal').style.display = 'none';
            document.body.style.overflow = 'auto';
            resetForm();
        }

        function resetForm() {
            document.getElementById('uploadForm').reset();
            document.getElementById('mediaPreview').classList.add('hidden');
            document.getElementById('imagePreview').classList.add('hidden');
            document.getElementById('videoPreview').classList.add('hidden');
        }

        function previewMedia(input) {
            const preview = document.getElementById('mediaPreview');
            const imagePreview = document.getElementById('imagePreview');
            const videoPreview = document.getElementById('videoPreview');
            
            preview.classList.remove('hidden');
            
            if (input.files && input.files[0]) {
                const file = input.files[0];
                const reader = new FileReader();
                
                reader.onload = function(e) {
                    if (file.type.startsWith('image/')) {
                        imagePreview.src = e.target.result;
                        imagePreview.classList.remove('hidden');
                        videoPreview.classList.add('hidden');
                    } else if (file.type.startsWith('video/')) {
                        videoPreview.src = e.target.result;
                        videoPreview.classList.remove('hidden');
                        imagePreview.classList.add('hidden');
                    }
                };
                
                reader.readAsDataURL(file);
            }
        }

        // Close modal when clicking outside
        document.getElementById('uploadModal').addEventListener('click', function(e) {
            if (e.target === this) {
                closeUploadModal();
            }
        });

        async function likeStatus(postId) {
            const response = await fetch('/api/like_status', {
                method: 'POST',
                headers: {'Content-Type': 'application/json'},
                body: JSON.stringify({status_id: postId})
            });
            
            const result = await response.json();
            if (result.ok) {
                location.reload();
            }
        }
        
        async function addComment(postId) {
            const commentInput = document.getElementById('comment-' + postId);
            const comment = commentInput.value.trim();
            
            if (comment) {
                const response = await fetch('/api/comment_status', {
                    method: 'POST',
                    headers: {'Content-Type': 'application/json'},
                    body: JSON.stringify({
                        status_id: postId,
                        comment: comment
                    })
                });
                
                const result = await response.json();
                if (result.ok) {
                    location.reload();
                }
            }
        }
        
        function toggleComments(postId) {
            const commentsSection = document.getElementById('comments-' + postId);
            commentsSection.classList.toggle('hidden');
        }
    </script>
</body>
</html>
"""

CREATE_LEAGUE_HTML = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Create League -GEx</title>
    <script src="https://cdn.tailwindcss.com"></script>
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css">
    <style>
        body {
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            min-height: 100vh;
        }
    </style>
</head>
<body class="min-h-screen">
    <div class="max-w-2xl mx-auto px-4 py-6">
        <header class="bg-white rounded-2xl shadow-md p-6 mb-6 flex justify-between items-center">
            <div>
                <h1 class="text-3xl font-bold text-purple-800">Create New League</h1>
                <p class="text-purple-700">Start your own 10-team league</p>
            </div>
            <a href="/" class="px-4 py-2 rounded-xl bg-purple-100 text-purple-700 hover:bg-purple-200 transition">
                <i class="fas fa-home mr-2"></i>Home
            </a>
        </header>

        <div class="bg-white rounded-2xl shadow-md p-6">
            {% if error %}
            <div class="bg-red-100 border border-red-400 text-red-700 px-4 py-3 rounded mb-4">
                {{ error }}
            </div>
            {% endif %}
            
            <form method="POST" enctype="multipart/form-data">
                <div class="mb-4">
                    <label for="name" class="block text-gray-700 text-sm font-bold mb-2">League Name</label>
                    <input type="text" id="name" name="name" required 
                        class="shadow appearance-none border rounded w-full py-2 px-3 text-gray-700 leading-tight focus:outline-none focus:shadow-outline">
                </div>
                
                <div class="mb-4">
                    <label for="game_type" class="block text-gray-700 text-sm font-bold mb-2">Game Type</label>
                    <select id="game_type" name="game_type" required 
                        class="shadow appearance-none border rounded w-full py-2 px-3 text-gray-700 leading-tight focus:outline-none focus:shadow-outline">
                        <option value="">Select Game Type</option>
                        <option value="fc_mobile">FC Mobile</option>
                        <option value="efootball">eFootball</option>
                    </select>
                </div>
                
                <div class="mb-4">
                    <label for="logo" class="block text-gray-700 text-sm font-bold mb-2">League Logo</label>
                    <input type="file" id="logo" name="logo" accept="image/*" 
                        class="shadow appearance-none border rounded w-full py-2 px-3 text-gray-700 leading-tight focus:outline-none focus:shadow-outline">
                </div>
                
                <div class="mb-6">
                    <label for="reward" class="block text-gray-700 text-sm font-bold mb-2">Winner Reward</label>
                    <input type="text" id="reward" name="reward" 
                        class="shadow appearance-none border rounded w-full py-2 px-3 text-gray-700 leading-tight focus:outline-none focus:shadow-outline"
                        placeholder="e.g., $100, Trophy, etc.">
                </div>
                
                <div class="flex items-center justify-between">
                    <button type="submit" class="bg-purple-600 hover:bg-purple-700 text-white font-bold py-2 px-4 rounded focus:outline-none focus:shadow-outline w-full">
                        Create League
                    </button>
                </div>
            </form>
        </div>
    </div>
</body>
</html>
"""

LEAGUE_HTML = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>{{ league.name }} -GEx</title>
    <script src="https://cdn.tailwindcss.com"></script>
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css">
    <style>
        body {
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            min-height: 100vh;
        }
    </style>
</head>
<body class="min-h-screen">
    <div class="max-w-7xl mx-auto px-4 py-6">
        <header class="bg-white rounded-2xl shadow-md p-6 mb-6 flex justify-between items-center">
            <div class="flex items-center">
                {% if league.logo %}
                <img src="{{ league.logo }}" class="w-16 h-16 rounded-full mr-4">
                {% endif %}
                <div>
                    <h1 class="text-3xl font-bold text-purple-800">{{ league.name }}</h1>
                    <p class="text-purple-700">{{ league.game_type|title }} • {{ league.status|title }}</p>
                    {% if league.reward %}
                    <p class="text-green-600 font-semibold">🏆 Reward: {{ league.reward }}</p>
                    {% endif %}
                </div>
            </div>
            <div class="flex gap-3">
                <a href="/" class="px-4 py-2 rounded-xl bg-purple-100 text-purple-700 hover:bg-purple-200 transition">
                    <i class="fas fa-home mr-2"></i>Home
                </a>
            </div>
        </header>

        <div class="grid grid-cols-1 md:grid-cols-3 gap-6 mb-6">
            <div class="bg-white rounded-2xl shadow-md p-5 text-center">
                <h3 class="text-lg font-semibold text-gray-700 mb-3">Teams</h3>
                <p class="text-3xl font-bold text-purple-700">{{ league.teams|length }}/10</p>
            </div>
            <div class="bg-white rounded-2xl shadow-md p-5 text-center">
                <h3 class="text-lg font-semibold text-gray-700 mb-3">Your Team</h3>
                <p class="text-xl font-bold text-purple-700">
                    {% if user_team %}
                    {{ user_team.name }}
                    {% else %}
                    Not Joined
                    {% endif %}
                </p>
            </div>
            <div class="bg-white rounded-2xl shadow-md p-5 text-center">
                <h3 class="text-lg font-semibold text-gray-700 mb-3">Status</h3>
                <p class="text-xl font-bold text-purple-700">{{ league.status|title }}</p>
            </div>
        </div>

        <!-- League Table -->
        <section class="bg-white rounded-2xl shadow-md p-6 mb-6">
            <h2 class="text-2xl font-bold text-purple-800 mb-4">League Table</h2>
            <div class="overflow-x-auto">
                <table class="min-w-full text-sm">
                    <thead class="bg-gray-100">
                        <tr>
                            <th class="p-3 text-left">#</th>
                            <th class="p-3 text-left">Team</th>
                            <th class="p-3 text-center">MP</th>
                            <th class="p-3 text-center">W</th>
                            <th class="p-3 text-center">D</th>
                            <th class="p-3 text-center">L</th>
                            <th class="p-3 text-center">GF</th>
                            <th class="p-3 text-center">GA</th>
                            <th class="p-3 text-center">GD</th>
                            <th class="p-3 text-center">Pts</th>
                        </tr>
                    </thead>
                    <tbody>
                        {% for row in table %}
                        <tr class="{{ 'bg-purple-50' if loop.index <= 4 else 'bg-yellow-50' if loop.index >= (table|length - 3) else '' }}">
                            <td class="p-3 font-medium">{{ loop.index }}</td>
                            <td class="p-3 font-medium flex items-center">
                                {% if row.logo %}
                                <img src="{{ row.logo }}" class="w-8 h-8 rounded-full mr-2">
                                {% endif %}
                                {{ row.team }}
                            </td>
                            <td class="p-3 text-center">{{ row.MP }}</td>
                            <td class="p-3 text-center">{{ row.W }}</td>
                            <td class="p-3 text-center">{{ row.D }}</td>
                            <td class="p-3 text-center">{{ row.L }}</td>
                            <td class="p-3 text-center">{{ row.GF }}</td>
                            <td class="p-3 text-center">{{ row.GA }}</td>
                            <td class="p-3 text-center {{ 'text-green-600' if row.GD > 0 else 'text-red-600' if row.GD < 0 else '' }}">{{ row.GD }}</td>
                            <td class="p-3 text-center font-bold">{{ row.Pts }}</td>
                        </tr>
                        {% endfor %}
                    </tbody>
                </table>
            </div>
        </section>

        <!-- Fixtures -->
        <section class="bg-white rounded-2xl shadow-md p-6">
            <h2 class="text-2xl font-bold text-purple-800 mb-4">Fixtures by Round</h2>
            <div class="grid grid-cols-2 sm:grid-cols-4 md:grid-cols-6 lg:grid-cols-8 gap-3 mb-6">
                {% for r in rounds %}
                <a href="/league/{{ league.id }}/round/{{ r }}" class="rounded-lg py-3 text-center bg-purple-100 text-purple-700 hover:bg-purple-200 transition">
                    Round {{ r }}
                </a>
                {% endfor %}
            </div>
        </section>
    </div>
</body>
</html>
"""

LEAGUE_ROUND_HTML = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Round {{ round_num }} - {{ league.name }}</title>
    <script src="https://cdn.tailwindcss.com"></script>
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css">
    <style>
        body {
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            min-height: 100vh;
        }
    </style>
</head>
<body class="min-h-screen">
    <div class="max-w-4xl mx-auto px-4 py-6">
        <header class="bg-white rounded-2xl shadow-md p-6 mb-6 flex justify-between items-center">
            <div>
                <h1 class="text-3xl font-bold text-purple-800">Round {{ round_num }}</h1>
                <p class="text-purple-700">{{ league.name }}</p>
            </div>
            <a href="/league/{{ league.id }}" class="px-4 py-2 rounded-xl bg-purple-100 text-purple-700 hover:bg-purple-200 transition">
                <i class="fas fa-arrow-left mr-2"></i>Back to League
            </a>
        </header>

        <div class="bg-white rounded-2xl shadow-md p-6">
            <h2 class="text-xl font-semibold mb-4">Matches</h2>
            <div class="grid gap-4">
                {% for match in matches %}
                <div class="border rounded-xl p-4 hover:shadow-md transition">
                    <div class="flex justify-between items-center mb-3">
                        <span class="text-sm text-gray-500">Match #{{ match.id }}</span>
                        <span class="text-sm {{ 'text-green-600' if match.completed else 'text-yellow-600' }}">
                            {{ 'Completed' if match.completed else 'Pending' }}
                        </span>
                    </div>
                    
                    <div class="grid grid-cols-5 items-center gap-3 mb-3">
                        <div class="col-span-2 text-right font-semibold truncate">{{ match.home }}</div>
                        <div class="col-span-1 flex justify-center items-center">
                            <input type="number" min="0" max="99" class="w-14 border rounded-md p-2 text-center" 
                                value="{{ match.home_goals if match.home_goals is not none else '' }}" 
                                id="hg-{{ match.id }}">
                            <span class="mx-2">:</span>
                            <input type="number" min="0" max="99" class="w-14 border rounded-md p-2 text-center" 
                                value="{{ match.away_goals if match.away_goals is not none else '' }}" 
                                id="ag-{{ match.id }}">
                        </div>
                        <div class="col-span-2 font-semibold truncate">{{ match.away }}</div>
                    </div>
                    
                    <div class="flex gap-2">
                        <button class="px-3 py-1.5 rounded-lg bg-purple-600 text-white hover:bg-purple-700 transition" 
                                onclick="saveScore({{ league.id }}, {{ match.id }})">
                            <i class="fas fa-save mr-1"></i>Save Score
                        </button>
                        <button class="px-3 py-1.5 rounded-lg border border-gray-300 hover:bg-gray-100 transition" 
                                onclick="clearScore({{ league.id }}, {{ match.id }})">
                            <i class="fas fa-times mr-1"></i>Clear
                        </button>
                    </div>
                </div>
                {% endfor %}
            </div>
        </div>
    </div>

    <script>
        async function saveScore(leagueId, matchId) {
            const hg = document.getElementById('hg-' + matchId).value;
            const ag = document.getElementById('ag-' + matchId).value;
            
            const response = await fetch('/api/update_score', {
                method: 'POST',
                headers: {'Content-Type': 'application/json'},
                body: JSON.stringify({
                    league_id: leagueId,
                    match_id: matchId,
                    home_goals: hg,
                    away_goals: ag
                })
            });
            
            const result = await response.json();
            if (result.ok) {
                alert('Score saved successfully!');
                location.reload();
            } else {
                alert('Error: ' + result.error);
            }
        }
        
        async function clearScore(leagueId, matchId) {
            document.getElementById('hg-' + matchId).value = '';
            document.getElementById('ag-' + matchId).value = '';
            
            await fetch('/api/update_score', {
                method: 'POST',
                headers: {'Content-Type': 'application/json'},
                body: JSON.stringify({
                    league_id: leagueId,
                    match_id: matchId,
                    home_goals: '',
                    away_goals: ''
                })
            });
            
            alert('Score cleared!');
            location.reload();
        }
    </script>
</body>
</html>
"""
HOME_HTML = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>GEx</title>
    <script src="https://cdn.tailwindcss.com"></script>
    <script src="https://cdnjs.cloudflare.com/ajax/libs/socket.io/4.0.1/socket.io.js"></script>
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css">
    <style>
        :root {
            --bg-primary: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            --bg-secondary: white;
            --text-primary: #374151;
            --text-secondary: #6b7280;
            --border-color: #e5e7eb;
        }

        .dark-mode {
            --bg-primary: linear-gradient(135deg, #1e3a8a 0%, #581c87 100%);
            --bg-secondary: #1f2937;
            --text-primary: #f9fafb;
            --text-secondary: #d1d5db;
            --border-color: #374151;
        }

        body {
            background: var(--bg-primary);
            min-height: 100vh;
            color: var(--text-primary);
            transition: all 0.3s ease;
        }

        .bg-white {
            background-color: var(--bg-secondary);
        }

        .text-gray-800, .text-gray-700, .text-gray-600, .text-gray-500 {
            color: var(--text-primary);
        }

        .border-gray-200, .border-gray-300 {
            border-color: var(--border-color);
        }

        .notification {
            position: fixed;
            top: 20px;
            right: 20px;
            background: var(--bg-secondary);
            border-radius: 10px;
            box-shadow: 0 4px 12px rgba(0,0,0,0.15);
            padding: 15px;
            max-width: 300px;
            z-index: 1000;
            transform: translateX(400px);
            transition: transform 0.3s ease;
            color: var(--text-primary);
            border: 1px solid var(--border-color);
        }
        .notification.show {
            transform: translateX(0);
        }
        .chat-container {
            height: calc(100vh - 140px);
        }
        @media (max-width: 768px) {
            .chat-container {
                height: calc(100vh - 120px);
            }
        }
        .messages-container {
            height: calc(100% - 80px);
            overflow-y: auto;
        }
        .online-dot {
            width: 8px;
            height: 8px;
            background: #10B981;
            border-radius: 50%;
            display: inline-block;
        }
        .unread-badge {
            background: #EF4444;
            color: white;
            border-radius: 50%;
            width: 20px;
            height: 20px;
            display: flex;
            align-items: center;
            justify-content: center;
            font-size: 12px;
        }
        .content-section {
            transition: all 0.3s ease;
        }
        .hidden-section {
            display: none;
        }
        .message-self {
            background-color: #e9d5ff;
            margin-left: auto;
            max-width: 70%;
        }
        .message-other {
            background-color: #f3f4f6;
            max-width: 70%;
        }
        .dark-mode .message-other {
            background-color: #374151;
            color: #f9fafb;
        }
        .typing-indicator {
            display: none;
        }
        .message-actions {
            display: none;
            position: absolute;
            background: var(--bg-secondary);
            border: 1px solid var(--border-color);
            border-radius: 8px;
            box-shadow: 0 4px 12px rgba(0,0,0,0.15);
            z-index: 100;
        }
        .message:hover .message-actions {
            display: flex;
        }
        
        /* Groups specific styles */
        .groups-container {
            max-height: calc(100vh - 200px);
            overflow-y: auto;
        }
        .group-item {
            transition: all 0.2s ease;
            border-bottom: 1px solid var(--border-color);
        }
        .group-item:hover {
            background-color: #f8fafc;
        }
        .group-item:last-child {
            border-bottom: none;
        }

        @media (max-width: 768px) {
            .message-self, .message-other {
                max-width: 85%;
            }
        }

        /* Dark mode specific styles */
        .dark-mode .bg-gray-50 {
            background-color: #374151;
        }
        .dark-mode .bg-purple-100 {
            background-color: #4c1d95;
        }
        .dark-mode .text-purple-700 {
            color: #c4b5fd;
        }
        .dark-mode .bg-green-100 {
            background-color: #065f46;
        }
        .dark-mode .bg-orange-100 {
            background-color: #7c2d12;
        }
        .dark-mode .bg-blue-50 {
            background-color: #1e40af;
        }
        .dark-mode .bg-red-50 {
            background-color: #7f1d1d;
        }
        .dark-mode .group-item:hover {
            background-color: #374151;
        }
    </style>
</head>
<body class="min-h-screen">
    <!-- Notification Container -->
    <div id="notificationContainer"></div>

    <!-- Image Preview Modal -->
    <div id="imagePreviewModal" class="fixed inset-0 bg-black bg-opacity-75 flex items-center justify-center z-50 hidden">
        <div class="bg-white rounded-lg p-4 max-w-2xl max-h-2xl">
            <div class="flex justify-between items-center mb-4">
                <h3 class="text-lg font-semibold">Preview Image</h3>
                <button onclick="closeImagePreview()" class="text-gray-500 hover:text-gray-700">
                    <i class="fas fa-times"></i>
                </button>
            </div>
            <img id="previewImage" src="" class="max-w-full max-h-96 rounded">
            <div class="flex justify-end space-x-2 mt-4">
                <button onclick="closeImagePreview()" class="px-4 py-2 bg-gray-600 text-white rounded-lg hover:bg-gray-700">Cancel</button>
                <button onclick="sendImageMessage()" class="px-4 py-2 bg-purple-600 text-white rounded-lg hover:bg-purple-700">Send</button>
            </div>
        </div>
    </div>

    <div class="max-w-7xl mx-auto px-2 sm:px-4 py-2">
        <!-- Header -->
        <header class="bg-white rounded-2xl shadow-md p-3 mb-3 flex justify-between items-center">
            <div class="flex items-center space-x-2 sm:space-x-4">
                <!-- Hamburger Menu -->
                <button id="hamburger" class="p-2 bg-purple-100 rounded-lg hover:bg-purple-200 transition">
                    <i class="fas fa-bars text-purple-700 text-sm sm:text-base"></i>
                </button>
                
                <!-- Search Bar -->
                <div class="relative">
                    <input type="text" id="globalSearch" placeholder="Search..." 
                        class="w-32 sm:w-48 md:w-64 p-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-purple-500 focus:border-purple-500 pr-8 text-sm bg-white text-gray-800">
                    <button class="absolute right-2 top-1/2 transform -translate-y-1/2 text-gray-500 hover:text-purple-600">
                        <i class="fas fa-search text-xs sm:text-sm"></i>
                    </button>
                </div>

                <!-- Dark Mode Toggle -->
                <button id="darkModeToggle" class="p-2 bg-purple-100 rounded-lg hover:bg-purple-200 transition">
                    <i id="darkModeIcon" class="fas fa-moon text-purple-700 text-sm sm:text-base"></i>
                </button>
            </div>

            <div class="text-center">
                <h1 class="text-xl sm:text-2xl font-bold text-purple-800">GEx</h1>
                <p class="text-purple-700 text-xs sm:text-sm">Welcome, {{ username }}!</p>
            </div>
        </header>

        <!-- Hidden menu -->
        <div id="navMenu" class="hidden fixed top-0 left-0 w-full sm:w-64 h-full bg-white shadow-lg p-4 z-50">
            <div class="flex justify-between items-center mb-6">
                <h2 class="text-xl font-bold text-purple-800">Menu</h2>
                <button id="closeMenu" class="p-2 text-gray-500 hover:text-purple-700">
                    <i class="fas fa-times"></i>
                </button>
            </div>
            <ul class="space-y-2">
                <li>
                    <a href="/status" class="flex items-center p-3 rounded-lg bg-blue-50 text-blue-700 hover:bg-blue-100 transition">
                        <i class="fas fa-feather mr-3"></i>Status
                    </a>
                </li>
                <li>
                    <a href="/create_league" class="flex items-center p-3 rounded-lg text-purple-700 hover:bg-purple-50 transition">
                        <i class="fas fa-plus mr-3"></i>Create League
                    </a>
                </li>
                <li>
                    <a href="/create_group" class="flex items-center p-3 rounded-lg text-purple-700 hover:bg-purple-50 transition">
                        <i class="fas fa-users mr-3"></i>Create Group
                    </a>
                </li>
                <li>
                    <a href="/profile" class="flex items-center p-3 rounded-lg text-purple-700 hover:bg-purple-50 transition">
                        <i class="fas fa-user mr-3"></i>Profile
                    </a>
                </li>
                {% if is_admin %}
                <li>
                    <a href="/admin" class="flex items-center p-3 rounded-lg bg-red-50 text-red-700 hover:bg-red-100 transition">
                        <i class="fas fa-shield-alt mr-3"></i>Admin
                    </a>
                </li>
                {% endif %}
                <li>
                    <a href="/logout" class="flex items-center p-3 rounded-lg bg-red-50 text-red-600 hover:bg-red-100 transition">
                        <i class="fas fa-sign-out-alt mr-3"></i>Logout
                    </a>
                </li>
            </ul>
        </div>

        {% if error %}
        <div class="bg-red-100 border border-red-400 text-red-700 px-4 py-3 rounded mb-4">
            {{ error }}
        </div>
        {% endif %}

        <!-- Chat Section (Default - Full Page Like WhatsApp) -->
        <div id="chatSection" class="content-section">
            <div class="bg-white rounded-2xl shadow-md chat-container flex flex-col sm:flex-row">
                <!-- Users List Sidebar -->
                <div class="w-full sm:w-1/3 border-b sm:border-b-0 sm:border-r border-gray-200">
                    <div class="p-3 border-b border-gray-200">
                        <h3 class="text-lg font-semibold text-gray-800">Chats</h3>
                    </div>
                    <div class="overflow-y-auto h-48 sm:h-full">
                        <!-- Your Chats -->
                        <div class="p-2">
                            {% for chat in user_chats %}
                            <a href="/chat/{{ chat.user }}" 
                               class="flex items-center p-2 rounded-lg hover:bg-purple-50 transition border border-gray-100 relative mb-1">
                                <div class="flex items-center justify-between w-full">
                                    <div class="flex items-center min-w-0">
                                        <div class="relative">
                                            {% if users[chat.user] and users[chat.user].profile_picture %}
                                            <img src="{{ users[chat.user].profile_picture }}" class="w-8 h-8 rounded-full mr-2">
                                            {% else %}
                                            <div class="w-8 h-8 rounded-full bg-purple-100 flex items-center justify-center mr-2">
                                                <i class="fas fa-user text-purple-600 text-xs"></i>
                                            </div>
                                            {% endif %}
                                            <span class="online-dot absolute -bottom-1 -right-1"></span>
                                        </div>
                                        <div class="min-w-0 flex-1">
                                            <span class="font-medium text-gray-800 text-sm block truncate">{{ chat.user }}</span>
                                            {% if chat.last_message %}
                                            <span class="text-xs text-gray-600 truncate block">{{ chat.last_message.message }}</span>
                                            {% endif %}
                                        </div>
                                    </div>
                                    <div class="flex flex-col items-end flex-shrink-0 ml-2">
                                        {% if chat.last_message %}
                                        <span class="text-xs text-gray-500">{{ chat.last_message.timestamp[11:16] }}</span>
                                        {% endif %}
                                        {% if chat.unread > 0 %}
                                        <div class="unread-badge mt-1">
                                            {{ chat.unread }}
                                        </div>
                                        {% endif %}
                                    </div>
                                </div>
                            </a>
                            {% endfor %}
                        </div>

                        <!-- Start New Chat -->
                        <div class="p-3 border-t border-gray-200">
                            <h3 class="text-md font-semibold mb-2 text-gray-800">Start New Chat</h3>
                            <div class="space-y-1 max-h-32 sm:max-h-40 overflow-y-auto">
                                {% for user_key, user_data in users.items() %}
                                {% if user_key != username %}
                                <a href="/chat/{{ user_key }}" 
                                   class="flex items-center p-2 rounded-lg hover:bg-green-50 transition">
                                    <div class="relative">
                                        {% if user_data.profile_picture %}
                                        <img src="{{ user_data.profile_picture }}" class="w-6 h-6 rounded-full mr-2">
                                        {% else %}
                                        <div class="w-6 h-6 rounded-full bg-green-100 flex items-center justify-center mr-2">
                                            <i class="fas fa-user text-green-600 text-xs"></i>
                                        </div>
                                        {% endif %}
                                        <span class="online-dot absolute -bottom-1 -right-1"></span>
                                    </div>
                                    <span class="font-medium text-gray-800 text-sm">{{ user_key }}</span>
                                </a>
                                {% endif %}
                                {% endfor %}
                            </div>
                        </div>
                    </div>
                </div>

                <!-- Chat Area -->
                <div class="flex-1 flex flex-col">
                    <!-- Chat Header -->
                    <div class="p-4 border-b border-gray-200 bg-gray-50 rounded-tr-2xl flex-1 flex items-center justify-center">
                        <div class="text-center text-gray-500">
                            <i class="fas fa-comments text-3xl mb-2 text-purple-300"></i>
                            <p class="text-sm sm:text-base">Select a user to start chatting</p>
                            <p class="text-xs sm:text-sm mt-1">Your conversations are private and secure</p>
                        </div>
                    </div>
                </div>
            </div>
        </div>

        <!-- Leagues Section -->
        <div id="leaguesSection" class="content-section hidden-section">
            <div class="bg-white rounded-2xl shadow-md p-4 sm:p-6">
                <h2 class="text-xl sm:text-2xl font-bold text-green-800 mb-4">Leagues</h2>
                
                <!-- Your Leagues -->
                <div class="mb-6">
                    <h3 class="text-lg sm:text-xl font-semibold text-green-700 mb-3">Your Leagues</h3>
                    {% if user_leagues %}
                    <div class="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-3 sm:gap-4">
                        {% for league in user_leagues %}
                        <div class="border border-green-200 rounded-xl p-3 sm:p-4 hover:shadow-md transition">
                            <div class="flex items-center mb-2 sm:mb-3">
                                {% if league.logo %}
                                <img src="{{ league.logo }}" class="w-8 h-8 sm:w-12 sm:h-12 rounded-full mr-2 sm:mr-3">
                                {% else %}
                                <div class="w-8 h-8 sm:w-12 sm:h-12 rounded-full bg-green-100 flex items-center justify-center mr-2 sm:mr-3">
                                    <i class="fas fa-trophy text-green-600 text-sm sm:text-base"></i>
                                </div>
                                {% endif %}
                                <div>
                                    <h3 class="font-semibold text-sm sm:text-base">{{ league.name }}</h3>
                                    <p class="text-xs sm:text-sm text-gray-600">{{ league.game_type|title }}</p>
                                </div>
                            </div>
                            <div class="text-xs sm:text-sm text-gray-600 mb-2 sm:mb-3">
                                <div>Teams: {{ league.teams|length }}/10</div>
                                <div>Status: {{ league.status|title }}</div>
                                {% if league.reward %}
                                <div>Reward: {{ league.reward }}</div>
                                {% endif %}
                            </div>
                            <a href="/league/{{ league.id }}" class="w-full bg-green-600 text-white py-1 sm:py-2 px-3 sm:px-4 rounded-lg hover:bg-green-700 transition text-center block text-xs sm:text-sm">
                                Enter League
                            </a>
                        </div>
                        {% endfor %}
                    </div>
                    {% else %}
                    <p class="text-gray-600 text-center py-4 text-sm sm:text-base">You haven't joined any leagues yet.</p>
                    {% endif %}
                </div>

                <!-- Available Leagues -->
                <div>
                    <h3 class="text-lg sm:text-xl font-semibold text-purple-700 mb-3">Available Leagues</h3>
                    {% if available_leagues %}
                    <div class="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-3 sm:gap-4">
                        {% for league in available_leagues %}
                        <div class="border border-purple-200 rounded-xl p-3 sm:p-4 hover:shadow-md transition">
                            <div class="flex items-center mb-2 sm:mb-3">
                                {% if league.logo %}
                                <img src="{{ league.logo }}" class="w-8 h-8 sm:w-12 sm:h-12 rounded-full mr-2 sm:mr-3">
                                {% else %}
                                <div class="w-8 h-8 sm:w-12 sm:h-12 rounded-full bg-purple-100 flex items-center justify-center mr-2 sm:mr-3">
                                    <i class="fas fa-trophy text-purple-600 text-sm sm:text-base"></i>
                                </div>
                                {% endif %}
                                <div>
                                    <h3 class="font-semibold text-sm sm:text-base">{{ league.name }}</h3>
                                    <p class="text-xs sm:text-sm text-gray-600">{{ league.game_type|title }}</p>
                                </div>
                            </div>
                            <div class="text-xs sm:text-sm text-gray-600 mb-2 sm:mb-3">
                                <div>Teams: {{ league.teams|length }}/10</div>
                                <div>Creator: {{ league.creator }}</div>
                                {% if league.reward %}
                                <div>Reward: {{ league.reward }}</div>
                                {% endif %}
                            </div>
                            <form method="POST" action="/join_league/{{ league.id }}">
                                <button type="submit" class="w-full bg-purple-600 text-white py-1 sm:py-2 px-3 sm:px-4 rounded-lg hover:bg-purple-700 transition text-xs sm:text-sm">
                                    Join League
                                </button>
                            </form>
                        </div>
                        {% endfor %}
                    </div>
                    {% else %}
                    <p class="text-gray-600 text-center py-4 text-sm sm:text-base">No available leagues at the moment.</p>
                    {% endif %}
                </div>
            </div>
        </div>

        <!-- Groups Section - UPDATED TO WHATSAPP STYLE -->
        <div id="groupsSection" class="content-section hidden-section">
            <div class="bg-white rounded-2xl shadow-md overflow-hidden">
                <!-- Groups Header -->
                <div class="p-4 border-b border-gray-200 bg-gray-50">
                    <div class="flex justify-between items-center">
                        <h2 class="text-lg font-semibold text-gray-800">All Groups</h2>
                        <span class="text-sm text-gray-500">{{ (user_groups + available_groups)|length }} groups</span>
                    </div>
                </div>

                <!-- Groups List -->
                <div class="groups-container">
                    <!-- Your Groups Section -->
                    {% if user_groups %}
                    <div class="p-3 bg-blue-50 border-b border-blue-100">
                        <h3 class="text-sm font-semibold text-blue-800 flex items-center">
                            <i class="fas fa-users mr-2"></i>
                            Your Groups ({{ user_groups|length }})
                        </h3>
                    </div>
                    {% for group in user_groups %}
                    <div class="group-item p-4 flex items-center justify-between hover:bg-gray-50 cursor-pointer">
                        <div class="flex items-center space-x-4 flex-1 min-w-0">
                            <div class="relative flex-shrink-0">
                                {% if group.logo %}
                                <img src="{{ group.logo }}" class="w-12 h-12 rounded-full">
                                {% else %}
                                <div class="w-12 h-12 rounded-full bg-orange-100 flex items-center justify-center">
                                    <i class="fas fa-users text-orange-600"></i>
                                </div>
                                {% endif %}
                                <span class="online-dot absolute bottom-0 right-0 border-2 border-white"></span>
                            </div>
                            <div class="flex-1 min-w-0">
                                <div class="flex items-center justify-between">
                                    <h3 class="font-semibold text-gray-800 truncate">{{ group.name }}</h3>
                                    <span class="text-xs text-gray-500 ml-2 flex-shrink-0">
                                        {{ group.created_at[:10] }}
                                    </span>
                                </div>
                                <p class="text-sm text-gray-600 truncate mb-1">{{ group.description or "No description" }}</p>
                                <div class="flex items-center text-xs text-gray-500">
                                    <span class="flex items-center mr-3">
                                        <i class="fas fa-user-friends mr-1"></i>
                                        {{ group.members|length }} members
                                    </span>
                                    <span class="flex items-center">
                                        <i class="fas fa-crown mr-1 text-yellow-500"></i>
                                        {{ group.creator }}
                                    </span>
                                </div>
                            </div>
                        </div>
                        <div class="flex items-center space-x-2 ml-4 flex-shrink-0">
                            <a href="/group/{{ group.id }}" class="bg-orange-600 text-white px-4 py-2 rounded-lg hover:bg-orange-700 transition text-sm">
                                Open
                            </a>
                            <a href="/leave_group/{{ group.id }}" class="bg-red-600 text-white p-2 rounded-lg hover:bg-red-700 transition text-sm" 
                               onclick="return confirm('Leave {{ group.name }}?')" title="Leave Group">
                                <i class="fas fa-sign-out-alt"></i>
                            </a>
                        </div>
                    </div>
                    {% endfor %}
                    {% endif %}

                    <!-- Available Groups Section -->
                    {% if available_groups %}
                    <div class="p-3 bg-green-50 border-b border-green-100">
                        <h3 class="text-sm font-semibold text-green-800 flex items-center">
                            <i class="fas fa-user-plus mr-2"></i>
                            Available Groups ({{ available_groups|length }})
                        </h3>
                    </div>
                    {% for group in available_groups %}
                    <div class="group-item p-4 flex items-center justify-between hover:bg-gray-50 cursor-pointer">
                        <div class="flex items-center space-x-4 flex-1 min-w-0">
                            <div class="relative flex-shrink-0">
                                {% if group.logo %}
                                <img src="{{ group.logo }}" class="w-12 h-12 rounded-full">
                                {% else %}
                                <div class="w-12 h-12 rounded-full bg-green-100 flex items-center justify-center">
                                    <i class="fas fa-users text-green-600"></i>
                                </div>
                                {% endif %}
                                <span class="online-dot absolute bottom-0 right-0 border-2 border-white"></span>
                            </div>
                            <div class="flex-1 min-w-0">
                                <div class="flex items-center justify-between">
                                    <h3 class="font-semibold text-gray-800 truncate">{{ group.name }}</h3>
                                    <span class="text-xs text-gray-500 ml-2 flex-shrink-0">
                                        {{ group.created_at[:10] }}
                                    </span>
                                </div>
                                <p class="text-sm text-gray-600 truncate mb-1">{{ group.description or "No description" }}</p>
                                <div class="flex items-center text-xs text-gray-500">
                                    <span class="flex items-center mr-3">
                                        <i class="fas fa-user-friends mr-1"></i>
                                        {{ group.members|length }} members
                                    </span>
                                    <span class="flex items-center">
                                        <i class="fas fa-crown mr-1 text-yellow-500"></i>
                                        {{ group.creator }}
                                    </span>
                                </div>
                            </div>
                        </div>
                        <div class="ml-4 flex-shrink-0">
                            <a href="/join_group/{{ group.id }}" class="bg-green-600 text-white px-4 py-2 rounded-lg hover:bg-green-700 transition text-sm">
                                Join
                            </a>
                        </div>
                    </div>
                    {% endfor %}
                    {% endif %}

                    <!-- Empty State -->
                    {% if not user_groups and not available_groups %}
                    <div class="text-center py-12">
                        <div class="w-24 h-24 mx-auto mb-4 rounded-full bg-gray-100 flex items-center justify-center">
                            <i class="fas fa-users text-gray-400 text-3xl"></i>
                        </div>
                        <h3 class="text-lg font-semibold text-gray-600 mb-2">No Groups Available</h3>
                        <p class="text-gray-500 mb-6">Create the first group to start chatting with others!</p>
                        <a href="/create_group" class="bg-purple-600 text-white px-6 py-3 rounded-lg hover:bg-purple-700 transition">
                            <i class="fas fa-plus mr-2"></i>Create Your First Group
                        </a>
                    </div>
                    {% endif %}
                </div>

                <!-- Footer Stats -->
                <div class="p-4 border-t border-gray-200 bg-gray-50">
                    <div class="flex justify-between items-center text-sm text-gray-600">
                        <div class="flex items-center space-x-4">
                            <span class="flex items-center">
                                <i class="fas fa-users text-blue-500 mr-1"></i>
                                Your Groups: {{ user_groups|length }}
                            </span>
                            <span class="flex items-center">
                                <i class="fas fa-user-plus text-green-500 mr-1"></i>
                                Available: {{ available_groups|length }}
                            </span>
                        </div>
                        <div class="text-xs text-gray-500">
                            Total: {{ (user_groups + available_groups)|length }} groups
                        </div>
                    </div>
                </div>
            </div>
        </div>
    </div>

    <!-- Floating Buttons -->
    <div class="fixed bottom-4 right-4 flex flex-col space-y-2 sm:space-y-3 z-50">
        <button id="leaguesBtn" class="bg-green-600 text-white p-2 sm:p-3 rounded-full shadow-lg hover:bg-green-700 transition text-xs sm:text-sm">
            <i class="fas fa-trophy"></i>
        </button>
        <button id="groupsBtn" class="bg-orange-600 text-white p-2 sm:p-3 rounded-full shadow-lg hover:bg-orange-700 transition text-xs sm:text-sm">
            <i class="fas fa-users"></i>
        </button>
        <button id="chatBtn" class="bg-purple-600 text-white p-2 sm:p-3 rounded-full shadow-lg hover:bg-purple-700 transition text-xs sm:text-sm">
            <i class="fas fa-comments"></i>
        </button>
        <button id="statusBtn" class="bg-blue-600 text-white p-2 sm:p-3 rounded-full shadow-lg hover:bg-blue-700 transition text-xs sm:text-sm">
            <i class="fas fa-feather"></i>
        </button>
    </div>

    <script>
        const socket = io();
        const currentUser = "{{ username }}";

        // Initialize dark mode
        function initializeDarkMode() {
            const darkModeToggle = document.getElementById('darkModeToggle');
            const darkModeIcon = document.getElementById('darkModeIcon');
            const isDarkMode = localStorage.getItem('darkMode') === 'true';
            
            if (isDarkMode) {
                document.body.classList.add('dark-mode');
                darkModeIcon.classList.replace('fa-moon', 'fa-sun');
            }
            
            darkModeToggle.addEventListener('click', () => {
                document.body.classList.toggle('dark-mode');
                const isNowDark = document.body.classList.contains('dark-mode');
                
                if (isNowDark) {
                    darkModeIcon.classList.replace('fa-moon', 'fa-sun');
                } else {
                    darkModeIcon.classList.replace('fa-sun', 'fa-moon');
                }
                
                localStorage.setItem('darkMode', isNowDark);
            });
        }

        // Section switching
        function switchSection(section) {
            document.getElementById('chatSection').classList.add('hidden-section');
            document.getElementById('leaguesSection').classList.add('hidden-section');
            document.getElementById('groupsSection').classList.add('hidden-section');
            
            document.getElementById(section + 'Section').classList.remove('hidden-section');
        }

        // Floating buttons functionality
        document.getElementById('leaguesBtn').addEventListener('click', () => switchSection('leagues'));
        document.getElementById('groupsBtn').addEventListener('click', () => switchSection('groups'));
        document.getElementById('chatBtn').addEventListener('click', () => switchSection('chat'));
        document.getElementById('statusBtn').addEventListener('click', () => window.location.href = '/status');

        // Hamburger menu functionality
        document.getElementById('hamburger').addEventListener('click', function() {
            document.getElementById('navMenu').classList.remove('hidden');
        });
        
        document.getElementById('closeMenu').addEventListener('click', function() {
            document.getElementById('navMenu').classList.add('hidden');
        });

        // Socket connection
        socket.emit('user_online', {username: currentUser});

        // Handle new message notifications
        socket.on('new_message_notification', function(data) {
            showNotification(data);
        });

        function showNotification(data) {
            const container = document.getElementById('notificationContainer');
            const notification = document.createElement('div');
            notification.className = 'notification';
            
            let content = '';
            if (data.type === 'group') {
                content = `
                    <div class="flex items-start">
                        <div class="bg-green-100 p-2 rounded-full mr-3">
                            <i class="fas fa-users text-green-600"></i>
                        </div>
                        <div>
                            <h4 class="font-semibold text-gray-800 text-sm">${data.group_name}</h4>
                            <p class="text-sm text-gray-600">${data.sender}: ${data.message}</p>
                            <p class="text-xs text-gray-500 mt-1">${new Date(data.timestamp).toLocaleTimeString()}</p>
                        </div>
                    </div>
                `;
            } else {
                content = `
                    <div class="flex items-start">
                        <div class="bg-blue-100 p-2 rounded-full mr-3">
                            <i class="fas fa-user text-blue-600"></i>
                        </div>
                        <div>
                            <h4 class="font-semibold text-gray-800 text-sm">${data.sender}</h4>
                            <p class="text-sm text-gray-600">${data.message}</p>
                            <p class="text-xs text-gray-500 mt-1">${new Date(data.timestamp).toLocaleTimeString()}</p>
                        </div>
                    </div>
                `;
            }
            
            notification.innerHTML = content;
            container.appendChild(notification);
            
            setTimeout(() => {
                notification.classList.add('show');
            }, 100);
            
            setTimeout(() => {
                notification.classList.remove('show');
                setTimeout(() => {
                    if (notification.parentNode) {
                        notification.parentNode.removeChild(notification);
                    }
                }, 300);
            }, 5000);
        }

        // Search functionality
        document.getElementById('globalSearch').addEventListener('input', function(e) {
            const searchTerm = e.target.value.toLowerCase();
            
            // Search in chat users
            const userItems = document.querySelectorAll('#chatSection a[href*="/chat/"]');
            userItems.forEach(item => {
                const text = item.textContent.toLowerCase();
                item.style.display = text.includes(searchTerm) ? 'flex' : 'none';
            });
        });

        // Add click functionality to group items
        document.addEventListener('DOMContentLoaded', function() {
            const groupItems = document.querySelectorAll('.group-item');
            
            groupItems.forEach(item => {
                item.addEventListener('click', function(e) {
                    // If click is not on a button, open the group
                    if (!e.target.closest('a')) {
                        const openLink = this.querySelector('a[href*="/group/"], a[href*="/join_group/"]');
                        if (openLink) {
                            openLink.click();
                        }
                    }
                });
            });
        });

        // Initialize
        document.addEventListener('DOMContentLoaded', function() {
            initializeDarkMode();
            switchSection('chat'); // Default to chat section
        });
    </script>
</body>
</html>
"""
if __name__ == "__main__":
    print("=== STARTING SERVER WITH GROUP FIXES ===")
    print(f"Initial groups in STATE: {list(STATE.get('groups', {}).keys())}")
    print(f"Next group ID: {STATE.get('next_group_id')}")
    socketio.run(app, host="0.0.0.0", port=5000, debug=True)