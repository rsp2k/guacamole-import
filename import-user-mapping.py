#!/usr/bin/env python

# Infomation about Guacamole Schema: https://guacamole.apache.org/doc/gug/jdbc-auth.html#jdbc-auth-schema-connections

import os, sys, getopt, random

import hashlib

import psycopg2

import xml.etree.ElementTree as ET

ROOT_GROUP_ID = None
BASE_GROUP_NAME = 'ISE'

def main(argv):
    try:
        opts, args = getopt.getopt(argv,"hi:b:",["ifile=","basefolder="])
    except getopt.GetoptError:
        print("Usage: %s -i <inputfile> -b <basefolder>" % (os.path.basename(__file__)))

    for opt, arg in opts:
        if opt == '-i':
            inputfile = arg
        if opt == '-b':
            BASE_GROUP_NAME = arg

    parse_user_mapping(inputfile)


def parse_user_mapping(inputfile):
    conn = db_connect()

    BASE_GROUP_ID = create_connection_group(conn, ROOT_GROUP_ID, BASE_GROUP_NAME)

    tree = ET.parse(inputfile)
    root = tree.getroot()
    for user in root.iter('authorize'):
        print(user.attrib)
        username = user.attrib['username']
        password = user.attrib['password']

        USER_ID = create_user(conn, username, password)

        USER_GROUP_ID = create_connection_group(conn, BASE_GROUP_ID, username)
        add_user_to_connection_group(conn,USER_ID, BASE_GROUP_ID)
        add_user_to_connection_group(conn,USER_ID, USER_GROUP_ID)

        for connection in user.iter('connection'):
            name = connection.attrib['name']
            protocol = connection.find('protocol').text
            print("%s: %s" % (protocol, name))

            parent_id = USER_GROUP_ID
            CONNECTION_ID = create_connection(conn, name, parent_id, protocol)
            add_user_to_connection(conn,USER_ID, CONNECTION_ID)
 
            for param in connection.iter('param'):
                name = param.attrib['name']
                value = param.text
                print("%s = %s" % (name, value))
                create_connection_parameter(conn, CONNECTION_ID, name, value)

            print("")

    conn.commit()
    conn.close()


def db_connect(**kwargs):
    conn = psycopg2.connect("dbname=guacamole_db host=127.0.0.1 user=guacamole_user")
    return conn


def create_connection(conn, name, parent_id, protocol):
# guacamole_connection (connection_id, connection_name, parent_id, protocol, max_connections, max_connections_per_user, connection_weight, failover_only, proxy_port, proxy_hostname, proxy_encryption_method)
    cur = conn.cursor()
    sql = "SELECT connection_id FROM guacamole_connection WHERE connection_name = %s AND protocol = %s AND parent_id = %s"

    row_exists = cur.execute(sql, (name, protocol, parent_id))
    if not row_exists:
        sql = "INSERT INTO guacamole_connection (connection_name, parent_id, protocol) VALUES(%s, %s, %s) RETURNING connection_id"
        cur.execute(sql, (name, parent_id, protocol))
    connection_id = cur.fetchone()[0] 
    cur.close()
    return connection_id

def create_connection_parameter(conn, connection_id, name, value):
# guacamole_connection_parameter (connection_id, parameter_name, parameter_value)
    cur = conn.cursor()

    sql = "SELECT 1 from guacamole_connection_parameter WHERE connection_id = %s and parameter_name = %s"
    row_exists = cur.execute(sql, (connection_id, name))
    if row_exists:
        sql = "UPDATE guacamole_connection_parameter SET parameter_value = %s WHERE connection_id = % AND parameter_name = %s"
        update_result = cur.execute(sql, (value, connection_id, name))
    else:
        sql = "INSERT INTO guacamole_connection_parameter (connection_id, parameter_name, parameter_value) VALUES(%s, %s, %s)"
        insert_result = cur.execute(sql, (connection_id, name, value))

    cur.close()
    return

def create_connection_group(conn, parent_id, name):
# guacamole_connection_group (connection_group_id, parent_id, connection_group_name, type, max_connections, max_connections_per_user, enable_session_affinity)
    cur = conn.cursor()
    sql = "SELECT connection_group_id FROM guacamole_connection_group WHERE connection_group_name = %s"
    row_exists = cur.execute(sql, (name,))
    if not row_exists:
        sql = "INSERT INTO guacamole_connection_group(parent_id, connection_group_name) VALUES(%s, %s) RETURNING connection_group_id"
        cur.execute(sql, (parent_id, name))

    connection_group_id = cur.fetchone()[0]
    cur.close()
    return connection_group_id

def add_user_to_connection(conn, user_id, connection_id):
    PERMISSION = 'READ'

    cur = conn.cursor()
    sql = "SELECT 1 FROM guacamole_connection_permission WHERE user_id = %s and connection_id = %s"
    row_exists = cur.execute(sql, (user_id, connection_id))
    if row_exists:
        sql = "UPDATE guacamole_connection_permission SET permission = %s WHERE user_id = %s and connection_id = %s"
        cur.execute(sql, (PERMISSION, user_id, connnection_id))
    else:
        sql = "INSERT INTO guacamole_connection_permission (user_id, connection_id, permission) VALUES (%s, %s, %s)"
        cur.execute(sql, (user_id, connection_id, PERMISSION))

    cur.close()
    return
 

def add_user_to_connection_group(conn, user_id, user_group_id):
    PERMISSION = 'READ'

    cur = conn.cursor()
    sql = "SELECT 1 FROM guacamole_connection_group_permission WHERE user_id = %s and connection_group_id = %s"
    row_exists = cur.execute(sql, (user_id, user_group_id))
    if row_exists:
        sql = "UPDATE guacamole_connection_group_permission SET permission = %s WHERE user_id = %s and connection_group_id = %s"
        cur.execute(sql, (PERMISSION, user_id, user_group_id))
    else:
        sql = "INSERT INTO guacamole_connection_group_permission (user_id, connection_group_id, permission) VALUES (%s, %s, %s)"
        cur.execute(sql, (user_id, user_group_id, PERMISSION))

    cur.close()
    return
    
def create_user(conn, username, password):
# guacamole_user (user_id, username, password_hash, password_salt, password_date, disabled, expired, access_window_start, access_window_end, valid_from, valid_until, timezone, full_name, email_address, organization, organizational_role) 
    salt = gen_salt()
    hp = hash_pass(password, salt)
    cur = conn.cursor()
    sql = "SELECT user_id from guacamole_user WHERE username = %s"
    cur.execute(sql, (username,))
    ret = cur.fetchone() 
    if ret:
        user_id = ret[0]
        sql = "UPDATE guacamole_user SET password_hash = decode(%s,'hex'), password_salt = decode(%s, 'hex')  WHERE user_id = %s"
        print(sql % (hp, salt, user_id))
        cur.execute(sql, (hp, salt, user_id))
        
    else:
        sql = "INSERT INTO guacamole_user (username, password_hash, password_salt, password_date) VALUES (%s, decode(%s,'hex'), decode(%s, 'hex'), CURRENT_TIMESTAMP) RETURNING user_id"

        cur.execute(sql, (username, hp, salt))
        user_id = cur.fetchone()[0]

    return user_id


def gen_salt():
    ALPHABET = "0123456789ABCDEF"
    chars=[]
    for i in range(32):
       chars.append(random.choice(ALPHABET))
    return "".join(chars)

def hash_pass(password, salt):
    p = password + salt
    m = hashlib.sha256()
    m.update(p)
    return m.hexdigest()

if __name__ == "__main__":
    main(sys.argv[1:])
