import requests

def check_link_status(url):

    try:
        response = requests.get(url, timeout=5)

        return {
            "status_code": response.status_code,
            "reachable": True
        }

    except:
        return {
            "status_code": None,
            "reachable": False
        }