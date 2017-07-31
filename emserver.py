import requests
import json
from time import time
from PIL import Image
import logging


API_HOST = 'http://a1.easemob.com/'
JSON_HEADER = {'Content-Type': 'application/json', 'Authorization': ''}
ORG_APP_NAME = 'ORG_NAME/APP_NAME' # like 1603/testapp
CLIENT_ID = 'YOUR_CLIENT_ID'
CLIENT_SECRET = 'YOUR_CLIENT_SECRET'
LOG_FORMAT = logging.Formatter('%(asctime)s %(message)s', datefmt='%Y-%m-%d %H:%M:%S')


def log(msg):
    c = logging.StreamHandler()
    c.setFormatter(LOG_FORMAT)
    logger = logging.Logger('err_log', logging.ERROR)
    logger.addHandler(c)
    logger.error(msg)


def parse_resp(r):
    if r.status_code == 200:
        return r.json()
    else:
        log('[code:%d] %s' % (r.status_code, r.text))
        return None


def get(url, headers=JSON_HEADER):
    r = requests.get(url, headers=headers)
    return parse_resp(r)


def post(url, payload=None, headers=JSON_HEADER, **kwargs):
    if payload:
        r = requests.post(url, headers=headers, data=json.dumps(payload), **kwargs)
    else:
        r = requests.post(url, headers=headers, **kwargs)
    return parse_resp(r)


def delete(url, headers=JSON_HEADER):
    r = requests.delete(url, headers=headers)
    return parse_resp(r)


def put(url, payload, headers=JSON_HEADER):
    r = requests.put(url, data=json.dumps(payload), headers=headers)
    return parse_resp(r)


class TokenManager(object):

    __token = ''
    __expires_in = 0
    __url = API_HOST + ORG_APP_NAME + '/token'
    __body = {
            "grant_type": "client_credentials",
            "client_id": CLIENT_ID,
            "client_secret": CLIENT_SECRET
    }

    @classmethod
    def token(cls):
        cls.refresh()
        return cls.__token

    @classmethod
    def get_token(cls):
        r = cls._acquire()
        if r:
            cls.__token = r['access_token']
            cls.__expires_in = int(r['expires_in']) + int(time())*100
            JSON_HEADER['Authorization'] = 'Bearer ' + cls.__token
        else:
            cls.__token = ''
            cls.__expires_in = 0

    @classmethod
    def is_valid(cls):
        return time() > (cls.__expires_in + 60) and cls.__expires_in

    @classmethod
    def refresh(cls):
        if not cls.is_valid():
            cls.get_token()

    @classmethod
    def _acquire(cls):
        return post(cls.__url, payload=cls.__body)


class UserManager(object):

    def __init__(self):
        self._url = API_HOST + ORG_APP_NAME + '/users'

    def register(self, username, password, nickname):
        if not nickname:
            nickname = 'nickname'
        return post(self._url, payload={'username': username, 'password': password, 'nickname': nickname})

    def get_blocks_users(self, username):
        return get(self._url + '/' + username + '/blocks/users')

    def add_blocks_user(self, username, user):
        return post(self._url + '/' + username + '/blocks/users', payload={'usernames': [user]})

    def remove_blocks_user(self, username, user):
        ":param user string"
        return delete(self._url + '/' + username + '/blocks/users/'+user)

    def get_info_of_contacts(self, username):
        return get(self._url + '/' + username + '/contacts/users')

    def remove_user_from_contacts(self, username, user):
        return delete(self._url + '/' + username + '/contacts/users/' + user)

    def add_user_to_contacts(self, username, user):
        return post(self._url + '/' + username + '/contacts/users/' + user)

    def get_offline_msg_count(self, username):
        return get(self._url + '/' + username + '/offline_msg_count')

    def delete(self, username):
        "删除一个用户会删除以该用户为群主的所有群组和聊天室。"
        return delete(self._url + '/' + username)

    def get_user_info(self, username):
        return get(self._url + '/' + username)

    def alter_nickname(self, username, nickname):
        return put(self._url + '/' + username, payload={"nickname": nickname})

    def activate_user(self, username):
        return post(self._url + '/' + username + '/activate')

    def deactivate_user(self, username):
        return post(self._url + '/' + username + '/deactivate')

    def force_user_to_logout(self, username):
        return get(self._url + '/' + username + '/disconnect')

    def get_groups_of_user(self, username):
        return get(self._url + '/' + username + '/joined_chatgroups')

    def get_offline_msg_status(self, username, msg_id):
        "通过离线消息的 ID 查看用户的该条离线消息状态。消息ID可以通过获取聊天记录查询。"
        return get(self._url + '/' + username + '/offline_msg_status/' + str(msg_id))

    def update_password(self, username, password):
        return put(self._url + '/' + username + '/password', payload={'newpassword': password})

    def is_online(self, username):
        data = get(self._url+'/'+username+'/status')
        status = data['data'][username]
        if status == 'offline':
            return json.dumps({'result': False})
        elif status == 'online':
            return json.dumps({'result': True})


class MessageManager(object):

    def __init__(self):
        self.send_url = API_HOST + ORG_APP_NAME + '/messages'
        self.msg = {
              "target_type": "users",
              "target": [],
              "msg": {
                "type": "type",
                "msg": "msg"
              },
              "from": "username",
        }
        self.msg_url = API_HOST + ORG_APP_NAME + '/chatmessages'

    def send_text_msg(self, to, msg, username="admin"):
        text_msg = dict()
        text_msg.update(self.msg)
        text_msg["target"].append(to)
        text_msg["msg"]["type"] = "txt"
        text_msg["msg"]["msg"] = msg
        text_msg["from"] = username
        return post(self.send_url, payload=text_msg)

    def send_img_msg(self, to, filename, file, username="admin"):
        imag_msg = dict()
        imag_msg.update(self.msg)
        ex_f = FileManager()
        resp = ex_f.upload_file(file, filename)
        if not resp:
            return resp
        imag_msg["target"].append(to)
        imag_msg["msg"]["type"] = "img"
        imag_msg["msg"]["url"] = ex_f._url + '/' + resp["entities"][0]["uuid"]
        imag_msg["msg"]["filename"] = filename
        imag_msg["msg"]["secret"] = ex_f._url + '/' + resp["entities"][0]["share-secret"]
        # 在linux上，可能会有错误
        imag_msg["msg"]["size"] = {"width": Image.open(file).size[0], "height": Image.open(file).size[1]}
        imag_msg["from"] = username
        return post(self.send_url, payload=imag_msg)

    def send_cmd_msg(self, to, content, username='admin'):
        cmd_msg = dict()
        cmd_msg.update(self.msg)
        cmd_msg["target"].append(to)
        cmd_msg["msg"]["type"] = "cmd"
        cmd_msg["msg"]["action"] = content
        cmd_msg["from"] = username
        return post(self.send_url, payload=cmd_msg)

    # 约定一下接收到的是什么格式的timestamp
    def get_chat_msg(self, timestamp):
        return get(self.msg_url + '/' + str(timestamp))


class FileManager(object):

    def __init__(self):
        self._url = API_HOST + ORG_APP_NAME + '/chatfiles'

    def upload_file(self, file, filename='file'):
        headers = dict()
        headers['restrict-access'] = 'true'
        headers['Authorization'] = JSON_HEADER['Authorization']
        files = {'file': (filename, file)}
        resp = requests.post(self._url, files=files, headers=headers)
        return parse_resp(resp)

    def show_files(self, file_uuid, share_secret, file_name):
        if not file_name:
            file_name = 'filename'
        headers = dict()
        headers['share_secret'] = share_secret
        headers['thumbnail'] = 'true'
        headers['Authorization'] = JSON_HEADER['Authorization']
        resp = requests.get(self._url + '/' + file_uuid, headers=headers)
        if 'error' in resp.text:
            return parse_resp(resp)
        else:
            return {file_name: resp.text}

    def download_file(self, file_uuid, share_secret, file_name):
        if not file_name:
            file_name = 'filename'
        headers = dict()
        headers['Authorization'] = JSON_HEADER['Authorization']
        headers['share-secret'] = share_secret
        resp = requests.get(self._url + '/' + file_uuid, headers=headers)
        if 'error' in resp.text:
            return parse_resp(resp)
        else:
            return {file_name: resp.text}


class GroupManager(object):

    def __init__(self):
        self._url = API_HOST + ORG_APP_NAME +'/chatgroups'

    def get_all_groups(self):
        pass

    def create_group(self, group_name, owner, members, public=True):
        if not isinstance(public, bool):
            public = True
        if not isinstance(members, list):
            members = [members]
        data = dict(groupname=group_name, owner=owner, members=members, public=public)
        return post(self._url, payload=data)

    def get_group_info(self, group_id):
        return get(self._url + '/' + str(group_id))

    def delete_group(self, group_id):
        return delete(self._url + '/' + str(group_id))

    def alter_group_info(self, group_id, **kwargs):
        ":param kwargs supposed: groupname or  description or maxusers\
        :param kwargs supposed: newowner"
        data = dict()
        if kwargs.get('newowner'):
            data["newowner"] = kwargs.get('newowner')
            return put(self._url + '/' + str(group_id), payload=data)
        if kwargs.get('groupname') and kwargs.get('groupname').find('/') == -1:
            data["groupname"] = kwargs.get('groupname').replace(' ', '+')
        if kwargs.get('description') and kwargs.get('description').find('/') == -1:
            data["description"] = kwargs.get('description').replace(' ', '+')
        if kwargs.get('maxusers'):
            data["maxusers"] = kwargs.get('maxusers')
        return put(self._url + '/' + str(group_id), payload=data)

    def get_blocks_users(self, group_id):
        return get(self._url + '/' + str(group_id) + '/blocks/users')

    def add_blocks_user(self, group_id, username):
        # return post(self._url + '/' + str(group_id) + '/blocks/users', payload={"usernames":[username]})
        return post(self._url + '/' + str(group_id) + '/blocks/users/' + username)

    def remove_user_from_blocks(self, group_id, username):
        return delete(self._url + '/' + str(group_id) + '/blocks/users/' + username)

    def get_group_members(self, group_id):
        return get(self._url + '/' + str(group_id) + '/' + 'users')

    def remove_member_from_group(self, group_id, username):
        return delete(self._url + '/' + str(group_id) + '/users/' + username)

    def add_group_user(self, group_id, username):
        return post(self._url + '/' + str(group_id) + '/users/' + username)

    def get_group_admins(self, group_id):
        return get(self._url + '/' + str(group_id) + '/admin')

    def add_group_admin(self, group_id, username):
        return post(self._url + '/' + str(group_id) + '/admin', payload={'newadmin': username})

    def reduce_group_admin(self, group_id, username):
        return delete(self._url + '/' + str(group_id) + '/admin/' + username)
