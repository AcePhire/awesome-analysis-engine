import vt
import sys
if __name__ == "__main__":
    api_key = sys.argv[1]
    client = vt.Client(api_key)
    sha256 = sys.argv[2]
    print(client.get_json(f"/files/{sha256}")["data"])
