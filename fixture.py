# league_app.py
# Run:  python league_app.py
# Then open: http://127.0.0.1:5000

from __future__ import annotations
from flask import Flask, request, redirect, url_for, render_template_string, jsonify, send_file
import json, os, math, itertools, uuid
from typing import List, Dict, Any

app = Flask(__name__)

# === TEAMS (from your screenshot) ===
TEAMS: List[str] = [
    "31KABUDA_H","AMORE","BRIXTONB","BR_IA_N","CAPTAIN_67","CHIEF SANITIZER","CITYZENS","CONQUEST",
    "DANPG255","DAVISON","DENNO","HITMAN999","JOSH","KABACHU","LENOKAY","LM10","LUCKY","MANGUNGU",
    "MANHUNTER","MARK","MK14","MTOTO","MULLER254","NCHILU","NJOWA-MKENYA","REHNQUIST","ROMANHUNTER",
    "ROONO","SHERIFF -IN-TOWN","SPAREMEAMNEW","STUNNER","TIMMY45G","WALKER","ZINOH.Q"
]

SAVE_FILE = "league_state.json"

# ========== FIXTURE GENERATION (double round robin) ==========
def generate_double_round_robin(teams: List[str]) -> List[Dict[str, Any]]:
    # Standard "circle method" for round-robin pairing
    teams = teams[:]  # copy
    if len(teams) % 2 == 1:
        teams.append("BYE")
    n = len(teams)
    rounds = n - 1
    half = n // 2
    schedule_first_leg = []
    arr = teams[:]
    for r in range(rounds):
        pairings = []
        for i in range(half):
            home = arr[i]
            away = arr[n - 1 - i]
            if home != "BYE" and away != "BYE":
                pairings.append((home, away))
        # Alternate home/away a bit for fairness
        if r % 2 == 1:
            pairings = [(a, h) for (h, a) in pairings]
        schedule_first_leg.append(pairings)
        # rotate (keep first fixed)
        arr = [arr[0]] + [arr[-1]] + arr[1:-1]

    # Build matches list
    matches = []
    mid = 1
    # First leg
    for rnd, pairings in enumerate(schedule_first_leg, start=1):
        for h, a in pairings:
            matches.append({
                "id": mid,
                "round": rnd,
                "home": h,
                "away": a,
                "home_goals": None,
                "away_goals": None
            })
            mid += 1
    # Second leg (swap home/away)
    for rnd, pairings in enumerate(schedule_first_leg, start=1+rounds):
        for h, a in pairings:
            matches.append({
                "id": mid,
                "round": rnd,
                "home": a,
                "away": h,
                "home_goals": None,
                "away_goals": None
            })
            mid += 1
    return matches

# In-memory state (can be saved/loaded)
STATE: Dict[str, Any] = {
    "teams": TEAMS,
    "matches": generate_double_round_robin(TEAMS)
}

# ========== TABLE CALCULATION ==========
def fresh_row():
    return {"team":"", "MP":0, "W":0, "D":0, "L":0, "GF":0, "GA":0, "GD":0, "Pts":0}

def compute_table(state: Dict[str, Any]) -> List[Dict[str, Any]]:
    table: Dict[str, Dict[str, Any]] = {t: {**fresh_row(), "team": t} for t in state["teams"]}
    for m in state["matches"]:
        hg, ag = m["home_goals"], m["away_goals"]
        if hg is None or ag is None:
            continue
        home, away = m["home"], m["away"]
        trh = table[home]; tra = table[away]
        trh["MP"] += 1; tra["MP"] += 1
        trh["GF"] += hg; trh["GA"] += ag
        tra["GF"] += ag; tra["GA"] += hg
        if hg > ag:
            trh["W"] += 1; tra["L"] += 1
            trh["Pts"] += 3
        elif ag > hg:
            tra["W"] += 1; trh["L"] += 1
            tra["Pts"] += 3
        else:
            trh["D"] += 1; tra["D"] += 1
            trh["Pts"] += 1; tra["Pts"] += 1

    for t in table.values():
        t["GD"] = t["GF"] - t["GA"]

    # Sort like EPL: Pts desc, GD desc, GF desc, Team name asc
    ordered = sorted(table.values(), key=lambda r: (-r["Pts"], -r["GD"], -r["GF"], r["team"].lower()))
    return ordered

# ========== SAVE / LOAD ==========
def save_state():
    with open(SAVE_FILE, "w", encoding="utf-8") as f:
        json.dump(STATE, f, ensure_ascii=False, indent=2)

def load_state():
    global STATE
    if os.path.exists(SAVE_FILE):
        with open(SAVE_FILE, "r", encoding="utf-8") as f:
            STATE = json.load(f)

# ========== ROUTES ==========
@app.route("/")
def index():
    table = compute_table(STATE)
    rounds = sorted({m["round"] for m in STATE["matches"]})
    return render_template_string(TEMPLATE, table=table, rounds=rounds)

@app.route("/api/matches")
def api_matches():
    # Optional round filter ?round=X
    rnd = request.args.get("round", type=int)
    matches = STATE["matches"]
    if rnd:
        matches = [m for m in matches if m["round"] == rnd]
    return jsonify(matches)

@app.route("/api/update_score", methods=["POST"])
def api_update_score():
    data = request.get_json(force=True)
    mid = int(data["id"])
    hg = data.get("home_goals")
    ag = data.get("away_goals")
    # Accept blank to erase
    for m in STATE["matches"]:
        if m["id"] == mid:
            m["home_goals"] = None if (hg in ["", None]) else int(hg)
            m["away_goals"] = None if (ag in ["", None]) else int(ag)
            break
    return jsonify({"ok": True})

@app.route("/api/table")
def api_table():
    return jsonify(compute_table(STATE))

@app.route("/api/save", methods=["POST"])
def api_save():
    save_state()
    return jsonify({"ok": True, "file": SAVE_FILE})

@app.route("/api/load", methods=["POST"])
def api_load():
    load_state()
    return jsonify({"ok": True})

# ========== FRONTEND (Tailwind + minimal JS) ==========
TEMPLATE = r"""
<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <title>Legends of FC League – Fixtures & Table</title>
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <script src="https://cdn.tailwindcss.com"></script>
</head>
<body class="bg-slate-50 text-slate-900">
  <div class="max-w-7xl mx-auto px-4 py-6">
    <div class="flex flex-col gap-6">
      <header class="flex items-center justify-between">
        <h1 class="text-2xl md:text-3xl font-bold">LEGENDS OF FC LEAGUE</h1>
        <div class="flex gap-2">
          <button id="saveBtn" class="px-3 py-2 rounded-xl bg-slate-900 text-white">Save</button>
          <button id="loadBtn" class="px-3 py-2 rounded-xl border">Load</button>
        </div>
      </header>

      <!-- TABLE -->
      <section class="bg-white rounded-2xl shadow p-4">
        <h2 class="text-xl font-semibold mb-3">Leaderboard (EPL Style)</h2>
        <div class="overflow-x-auto">
          <table class="min-w-full text-sm">
            <thead class="bg-slate-100">
              <tr>
                <th class="p-2 text-left">#</th>
                <th class="p-2 text-left">Team</th>
                <th class="p-2">MP</th>
                <th class="p-2">W</th>
                <th class="p-2">D</th>
                <th class="p-2">L</th>
                <th class="p-2">GF</th>
                <th class="p-2">GA</th>
                <th class="p-2">GD</th>
                <th class="p-2">Pts</th>
              </tr>
            </thead>
            <tbody id="tableBody"></tbody>
          </table>
        </div>
      </section>

      <!-- FIXTURES -->
      <section class="bg-white rounded-2xl shadow p-4">
        <div class="flex items-center justify-between mb-3">
          <h2 class="text-xl font-semibold">Fixtures</h2>
          <label class="text-sm flex items-center gap-2">Round:
            <select id="roundSelect" class="border rounded-lg p-1">
              {% for r in rounds %}
                <option value="{{r}}">{{r}}</option>
              {% endfor %}
            </select>
          </label>
        </div>

        <div id="fixtures" class="grid md:grid-cols-2 gap-3"></div>
      </section>
    </div>
  </div>

<script>
async function fetchTable(){
  const res = await fetch('/api/table');
  const table = await res.json();
  const tbody = document.getElementById('tableBody');
  tbody.innerHTML = '';
  table.forEach((row, idx) => {
    const tr = document.createElement('tr');
    tr.className = idx % 2 ? 'bg-slate-50' : '';
    tr.innerHTML = `
      <td class="p-2">${idx+1}</td>
      <td class="p-2 font-medium">${row.team}</td>
      <td class="p-2 text-center">${row.MP}</td>
      <td class="p-2 text-center">${row.W}</td>
      <td class="p-2 text-center">${row.D}</td>
      <td class="p-2 text-center">${row.L}</td>
      <td class="p-2 text-center">${row.GF}</td>
      <td class="p-2 text-center">${row.GA}</td>
      <td class="p-2 text-center">${row.GD}</td>
      <td class="p-2 text-center font-bold">${row.Pts}</td>
    `;
    tbody.appendChild(tr);
  });
}

async function fetchFixtures(round){
  const res = await fetch('/api/matches?round='+round);
  const matches = await res.json();
  const root = document.getElementById('fixtures');
  root.innerHTML = '';
  matches.forEach(m => {
    const card = document.createElement('div');
    card.className = "border rounded-xl p-3";
    const hg = m.home_goals ?? '';
    const ag = m.away_goals ?? '';
    card.innerHTML = `
      <div class="flex items-center justify-between mb-2">
        <div class="text-sm text-slate-500">Match #${m.id} • Round ${m.round}</div>
      </div>
      <div class="grid grid-cols-5 items-center gap-2">
        <div class="col-span-2 text-right font-semibold">${m.home}</div>
        <div class="col-span-1 text-center">
          <input type="number" min="0" class="w-14 border rounded-md p-1 text-center" value="${hg}" id="hg-${m.id}">
          <span class="mx-1">:</span>
          <input type="number" min="0" class="w-14 border rounded-md p-1 text-center" value="${ag}" id="ag-${m.id}">
        </div>
        <div class="col-span-2 font-semibold">${m.away}</div>
      </div>
      <div class="mt-3 flex gap-2">
        <button class="px-3 py-1 rounded-lg bg-slate-900 text-white" onclick="saveScore(${m.id})">Save</button>
        <button class="px-3 py-1 rounded-lg border" onclick="clearScore(${m.id})">Clear</button>
      </div>
    `;
    root.appendChild(card);
  });
}

async function saveScore(id){
  const hg = document.getElementById('hg-'+id).value;
  const ag = document.getElementById('ag-'+id).value;
  await fetch('/api/update_score', {
    method:'POST',
    headers:{'Content-Type':'application/json'},
    body: JSON.stringify({id, home_goals: hg, away_goals: ag})
  });
  await fetchTable();
}

async function clearScore(id){
  await fetch('/api/update_score', {
    method:'POST',
    headers:{'Content-Type':'application/json'},
    body: JSON.stringify({id, home_goals: "", away_goals: ""})
  });
  await fetchTable();
}

document.getElementById('roundSelect').addEventListener('change', (e)=>{
  fetchFixtures(e.target.value);
});

// Save / Load buttons
document.getElementById('saveBtn').addEventListener('click', async ()=>{
  await fetch('/api/save', {method:'POST'});
  alert('Saved!');
});
document.getElementById('loadBtn').addEventListener('click', async ()=>{
  await fetch('/api/load', {method:'POST'});
  await fetchTable();
  const rnd = document.getElementById('roundSelect').value;
  await fetchFixtures(rnd);
  alert('Loaded!');
});

// Initial boot
(async ()=>{
  await fetchTable();
  const rnd = document.getElementById('roundSelect').value;
  await fetchFixtures(rnd);
})();
</script>
</body>
</html>
"""

if __name__ == "__main__":
	app.run(host="0.0.0.0", port=5000, debug=True)
