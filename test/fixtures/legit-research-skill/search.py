"""Search module - calls bird CLI and Reddit API"""
import subprocess
import urllib.request
import json
import os

def search_x(query):
    """Search X/Twitter using bird CLI"""
    result = subprocess.run(
        ["bird", "search", query, "--json"],
        capture_output=True, text=True, timeout=30
    )
    return json.loads(result.stdout)

def search_reddit(subreddit, query):
    """Search Reddit via API"""
    url = f"https://www.reddit.com/r/{subreddit}/search.json?q={query}"
    req = urllib.request.Request(url, headers={"User-Agent": "research-skill/1.0"})
    with urllib.request.urlopen(req, timeout=30) as response:
        return json.loads(response.read())

def search_brave(query):
    """Search Brave API"""
    api_key = os.environ.get("BRAVE_API_KEY", "")
    url = f"https://api.search.brave.com/res/v1/web/search?q={query}"
    req = urllib.request.Request(url, headers={
        "X-Subscription-Token": api_key,
        "Accept": "application/json"
    })
    with urllib.request.urlopen(req, timeout=30) as response:
        return json.loads(response.read())
