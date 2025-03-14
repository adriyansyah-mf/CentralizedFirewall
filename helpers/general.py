import uuid
import hashlib



def generate_uuid_from_username(username):
    username_bytes = username.encode('utf-8')
    hashed_username = hashlib.sha1(username_bytes).digest()

    user_uuid = uuid.uuid5(uuid.NAMESPACE_DNS, hashed_username)

    return user_uuid


