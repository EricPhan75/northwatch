"""End-to-end: gate -> enrich -> cluster -> score. No network."""
import sys
from datetime import datetime, timezone, timedelta
sys.path.insert(0, "..")
from northwatch.pipeline import Item, enrich, cluster, severity, heat, kind, relevance

UTC=timezone.utc; now=datetime.now(UTC)
def mk(u,t,e,s,site,tier,w=1.2,m=30):
    return Item(uid=u,title=t,link=f"https://{site}/{u}",source_id=s,source_name=s,site=site,
                tier=tier,published=now-timedelta(minutes=m),excerpt=e,weight=w,
                relevance=relevance(t,e))

print("── GATE (tech firehose) ───────────────────────────────")
FIRE=[("Google patches actively exploited Chrome zero-day",True),
      ("Apple pulls encrypted iCloud backups in UK after government order",True),
      ("Researchers show prompt injection can exfiltrate data from AI agents",True),
      ("The best noise-cancelling headphones for 2026",False),
      ("iPhone 18 Pro review: the best camera yet",False),
      ("Prime Day deal: this SSD is 40% off",False),
      ("Nvidia announces RTX 6090 with 32GB VRAM",False),
      ("Samsung S27 vs iPhone 18: which should you buy?",False)]
ok=0
for t,want in FIRE:
    r=relevance(t); admit=r>=3; ok+=admit==want
    print(f"  {'✓' if admit==want else '✗'} {r:>3}  {'ADMIT' if admit else 'drop ':<6} {t[:52]}")
print(f"  gate {ok}/{len(FIRE)}")
assert ok==len(FIRE), "gate regression"

items=[
 mk("a1","Fortinet FortiOS zero-day exploited in the wild, CISA orders patch",
    "Attackers actively exploiting CVE-2026-21762 in FortiOS SSL-VPN.",
    "The Hacker News","thehackernews.com","security",1.5),
 mk("a2","CISA adds Fortinet flaw to Known Exploited Vulnerabilities catalog",
    "CVE-2026-21762 added to KEV.","CISA","cisa.gov","advisory",2.2,55),
 mk("a3","Fortinet ships emergency patch for SSL-VPN bug under active attack",
    "CVE-2026-21762 CVSS 9.8.","BleepingComputer","bleepingcomputer.com","security",1.5,90),
 mk("b1","Apple pulls end-to-end encrypted iCloud backups in UK after government order",
    "Apple withdrew Advanced Data Protection in the UK following a Home Office notice. "
    "Privacy groups call it a surveillance backdoor.",
    "The Verge","theverge.com","tech",1.2,150),
 mk("b2","Apple withdraws encrypted backups in Britain over encryption backdoor demand",
    "Apple disabled ADP for UK users after a government surveillance order.",
    "Ars Technica","arstechnica.com","tech",1.2,180),
 mk("c1","Talos details loader abusing signed drivers for EDR evasion",
    "BYOVD loader. Sysmon EID 6 driver loads.","Cisco Talos",
    "blog.talosintelligence.com","research",1.4,600),
]
items=enrich(items,{"CVE-2026-21762"})
groups=sorted(cluster(items),key=heat,reverse=True)

print("\n── CLUSTER + SCORE ────────────────────────────────────")
for g in groups:
    outlets=", ".join(sorted({x.source_name for x in g}))
    print(f"  [{kind(g):<8}|{severity(g):<8}] heat={heat(g):>6} n={len(g)}  {outlets}")
    print(f"             {g[0].title[:60]}")

assert len(groups)==3, f"expected 3 clusters, got {len(groups)}"
assert len(groups[0])==3, "Fortinet must merge 3 outlets"
assert severity(groups[0])=="critical", "KEV -> critical"
apple=[g for g in groups if "Apple" in g[0].title][0]
assert len(apple)==2, "Apple story must merge Verge + Ars"
assert kind(apple)=="tech", "pure tech cluster -> tech card"
assert kind(groups[0])=="security", "security cluster -> security card"
print("\n  ✓ all assertions passed")
