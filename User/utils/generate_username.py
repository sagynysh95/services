def generate_username(cls, values):
    name = values.get("name")
    surname = values.get("surname")
    username = f"{name[:1]}.{surname}"
    # if mongo_get_username(username):
    #     values["username"] = username
    # values["username"] = f"{name}.{surname}"
    return values