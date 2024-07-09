#!/usr/bin/python3
#
# coding=utf-8
# DuckDNS updates with MQTT status reporting

import os
import socket
import requests
from datetime import datetime
from datetime import timedelta
import logging.handlers
import time
import json
import platform
import paho.mqtt.client as mqtt

LOG_FILENAME = '/var/log/dyndns/dyndns.log'
HA_ICON = "mdi:binoculars"

UPDATE_INTERVAL = int(os.getenv("UPDATE_INTERVAL", "5"))
FORCE_UPDATE_INTERVAL = int(os.getenv("UPDATE_INTERVAL", "900"))

DUCKDNS_DOMAIN = os.getenv("DUCKDNS_DOMAIN", None)
DUCKDNS_TOKEN = os.getenv("DUCKDNS_TOKEN", None)

DYNDNS_URL = os.getenv("DYNDNS_URL", None)
DYNDNS_DOMAIN = os.getenv("DYNDNS_DOMAIN")

MQTT_BROKER = os.getenv("MQTT_BROKER", "mqtt.local")
MQTT_USER = os.getenv("MQTT_USER", "mqtt")
MQTT_PASSWORD = os.getenv("MQTT_PASSWORD", "password")
MQTT_BASE_TOPIC = "dyndns"
MQTT_IPV4_TOPIC = "/ipv4"
MQTT_IP_QUERY_PROBLEM = "/ip-query-problem"
MQTT_DNS_QUERY_PROBLEM = "/dns-query-problem"
MQTT_DYNDNS_UPDATE_PROBLEM = "/dyndns-update-problem"
MQTT_IP_SYNC_PROBLEM = "/ip-sync-problem"

problem_status = dict()
external_ip = None
last_problem_time = None


def get_our_ip():
    try:
        r = requests.get('https://api.ipify.org/?format=json')
        if r.status_code == 200:
            log.debug("IPIFY: Got our external IP {ip}".format(ip=r.json()['ip']))
            return r.json()['ip']
    except:
        pass

    log.warning("IPIFY: Failed getting our external IP")
    return None


def update_dyndns_via_url():
    if DYNDNS_URL is not None:
        log.info("DynDNS: Updating via URL")
        try:
            r = requests.get(DYNDNS_URL)
            if r.status_code == 200:
                return True
            else:
                log.error("DynDNS: Update failed - check url")
                return False
        except:
            pass

        log.error("DynDNS: failed to access dynmaic DNS update URL")
    return None


def update_duck_dns():
    if DUCKDNS_DOMAIN is not None and DUCKDNS_TOKEN is not None:
        log.info("DuckDNS: Updating DuckDNS")
        try:
            url = "https://www.duckdns.org/update?domains={domains}&token={token}&ip=".format(
                domains=DUCKDNS_DOMAIN, token=DUCKDNS_TOKEN)
            r = requests.get(url)
            if r.status_code == 200:
                if r.content == b'OK':
                    return True
                else:
                    log.error("DuckDNS: Update failed - check domains and token")
                    return False
        except:
            pass

        log.error("DuckDNS: failed to access DuckDNS API")
    return None


def update_dns():
    """Update the Dynamic DNS records via all supported providers"""

    duck = update_duck_dns()
    dyn = update_dyndns_via_url()

    success =  None
    if duck is None:
        success = dyn
    elif dyn is None:
        success = duck
    else:
        success = duck and dyn

    return success

def on_connect(client, userdata, flags, rc):
    """The callback for when the client receives a CONNACK response from the server."""

    log.info("MQTT: Connected to broker with result code " + str(rc))

    client.publish(MQTT_BASE_TOPIC + "/status", payload="online")

    # update discovery each time we connect
    publish_home_assistant_discovery(client)


def on_message(client, userdata, msg):
    global last_problem_time
    payload = str(msg.payload, "UTF-8").strip()
    log.debug("MQTT: Message " + msg.topic + " = " + payload)
    if "/last-problem-time" in msg.topic:
        log.info("MQTT: received last problem time {dt}".format(dt=payload))
        dt = datetime.fromisoformat(payload)
        if dt != last_problem_time:
            last_problem_time = dt


def record_problem_time(client, time):
    """Update last problem time and publish to MQTT"""
    global last_problem_time

    log.info("Recording last problem time as {when}".format(when=str(last_problem_time.isoformat())))
    last_problem_time = time
    client.publish(MQTT_BASE_TOPIC + "/last-problem-time", payload=str(last_problem_time.isoformat()), retain=True)


def record_problem(client, topic: str, ok: bool, when = datetime.now()):
    """Update last problem time and publish to MQTT"""
    global last_problem_time
    
    log.debug("Recording status on {topic} {status} time as {when}".format(topic=topic, status="OK" if ok else "Error", when=str(when.isoformat())))

    if topic not in problem_status or ok != problem_status[topic]:
        last_problem_time = when
        problem_status[topic] = ok
        client.publish(MQTT_BASE_TOPIC + "/last-problem-time", payload=str(when.isoformat()), retain=True)
        client.publish(MQTT_BASE_TOPIC + topic, payload="OFF" if ok else "ON")
    else:
        log.debug("Skipping MQTT for {topic} {ok} - state unchanged".format(topic=topic, ok=ok))


def record_ip_lookup(client, ok: bool) -> None:
    """Record result of looking up our public IP address"""
    record_problem(client, MQTT_IP_QUERY_PROBLEM, ok)


def record_dns_lookup(client, ok: bool) -> None:
    """Record result of looking DNS entry"""
    record_problem(client, MQTT_DNS_QUERY_PROBLEM, ok)


def record_dyndns_update(client, ok: bool) -> None:
    """Record result of the DynDNS update operation"""
    record_problem(client, MQTT_DYNDNS_UPDATE_PROBLEM, ok)


def record_ip_out_of_sync(client, ok: bool) -> None:
    """Record IP address mis-match status between our public IP and the DNS entry IP"""
    record_problem(client, MQTT_IP_SYNC_PROBLEM, ok)


def publish_ip_address(client, external_ip):
    """Publish the IP address to MQTT"""
    log.info("MQTT: publishing our IP address {ip}"
             .format(ip=external_ip))

    if MQTT_IPV4_TOPIC not in problem_status or external_ip != problem_status[MQTT_IPV4_TOPIC]:
        problem_status[MQTT_IPV4_TOPIC] = external_ip
        if external_ip is not None:
            ok = client.publish(MQTT_BASE_TOPIC + MQTT_IPV4_TOPIC, payload=external_ip, retain=True)
        else:
            ok = client.publish(MQTT_BASE_TOPIC + MQTT_IPV4_TOPIC, payload='None', retain=True)


def publish_status(client, external_ip, update_status):
    """Publish the DynDNS update status to MQTT"""
    log.info("MQTT: Publishing DyDNS update status for {ip} as {state} at {topic}"
             .format(ip=external_ip, state='OK' if update_status else 'Not OK', topic=MQTT_BASE_TOPIC + "/ipv4"))
    ok = client.publish(MQTT_BASE_TOPIC + "/ipv4", payload=external_ip, retain=True)
    log.debug("Publish status = {status}".format(status=ok))
    ok = client.publish(MQTT_BASE_TOPIC + "/published-entry-problem", payload='OFF' if update_status else 'ON', retain=True)


def publish_home_assistant_discovery(client):
    """Publish discovery for the two sensors"""
    log.info("MQTT: Publishing Home Assistant discovery data")
    payload = {
        "name": "DynDNS IPv4",
        "state_topic": "{base}{ipv4}".format(base=MQTT_BASE_TOPIC, ipv4=MQTT_IPV4_TOPIC),
        "availability_topic": "{base}/status".format(base=MQTT_BASE_TOPIC),
        "payload_available": "online",
        "payload_not_available": "offline",
        "unique_id": "{host}-dyndns-ipv4".format(host=platform.node()),
        "icon": HA_ICON
    }
    discovery_topic = "homeassistant/sensor/dyndns-ipv4/config"
    client.publish(discovery_topic, payload=json.dumps(payload), retain=True)

    payload = {
        "name": "DynDNS Update Problem",
        "state_topic": "{base}{topic}".format(base=MQTT_BASE_TOPIC, topic=MQTT_DYNDNS_UPDATE_PROBLEM),
        "availability_topic": "{base}/status".format(base=MQTT_BASE_TOPIC),
        "payload_available": "online",
        "payload_not_available": "offline",
        "device_class": "problem",
        "unique_id": "{host}-dyndns-update-problem".format(host=platform.node()),
        "icon": HA_ICON
    }
    discovery_topic = "homeassistant/binary_sensor/dyndns-update-problem/config"
    client.publish(discovery_topic, payload=json.dumps(payload), retain=True)

    payload = {
        "name": "DynDNS DNS Query Problem",
        "state_topic": "{base}{topic}".format(base=MQTT_BASE_TOPIC, topic=MQTT_DNS_QUERY_PROBLEM),
        "availability_topic": "{base}/status".format(base=MQTT_BASE_TOPIC),
        "payload_available": "online",
        "payload_not_available": "offline",
        "device_class": "problem",
        "unique_id": "{host}-dyndns-query-problem".format(host=platform.node()),
        "icon": HA_ICON
    }
    discovery_topic = "homeassistant/binary_sensor/dyndns-dns-query-problem/config"
    client.publish(discovery_topic, payload=json.dumps(payload), retain=True)

    payload = {
        "name": "DynDNS IP Query Problem",
        "state_topic": "{base}{topic}".format(base=MQTT_BASE_TOPIC, topic=MQTT_IP_QUERY_PROBLEM),
        "availability_topic": "{base}/status".format(base=MQTT_BASE_TOPIC),
        "payload_available": "online",
        "payload_not_available": "offline",
        "device_class": "problem",
        "unique_id": "{host}-dyndns-ip-query-problem".format(host=platform.node()),
        "icon": HA_ICON
    }
    discovery_topic = "homeassistant/binary_sensor/dyndns-ip-query-problem/config"
    client.publish(discovery_topic, payload=json.dumps(payload), retain=True)

    payload = {
        "name": "DynDNS IP Sync Problem",
        "state_topic": "{base}{topic}".format(base=MQTT_BASE_TOPIC, topic=MQTT_IP_SYNC_PROBLEM),
        "availability_topic": "{base}/status".format(base=MQTT_BASE_TOPIC),
        "payload_available": "online",
        "payload_not_available": "offline",
        "device_class": "problem",
        "unique_id": "{host}-dyndns-ip-sync-problem".format(host=platform.node()),
        "icon": HA_ICON
    }
    discovery_topic = "homeassistant/binary_sensor/dyndns-ip-sync-problem/config"
    client.publish(discovery_topic, payload=json.dumps(payload), retain=True)


def dns_lookup():
    try:
        return set([str(i[4][0]) for i in socket.getaddrinfo(DYNDNS_DOMAIN, 80)])
    except:
        return None


def setup_mqtt():
    client = mqtt.Client(client_id="dynsdns-" + platform.node())
    client.loop_start()
    client.username_pw_set(MQTT_USER, MQTT_PASSWORD)
    client.on_connect = on_connect
    client.on_message = on_message
    client.max_queued_messages_set(10)
    client.will_set(MQTT_BASE_TOPIC + "/status", payload="offline")
    client.connect(MQTT_BROKER, 1883, keepalive=UPDATE_INTERVAL * 3)
    return client


def update():
    global last_problem_time

    while True:
        try:
            client = setup_mqtt()

            our_ip = get_our_ip()
            record_ip_lookup(client, our_ip is not None)

            log.info("External IP is {ip}".format(ip=our_ip))

            status = update_dns()
            record_dyndns_update(client, status)

            iterations_per_forced_update = int(FORCE_UPDATE_INTERVAL / UPDATE_INTERVAL)

            while True:
                for i in range(iterations_per_forced_update):
                    our_ip = get_our_ip()
                    publish_ip_address(client, our_ip)
                    record_ip_lookup(client, our_ip is not None)

                    dns_ips = dns_lookup()
                    record_dns_lookup(client, dns_ips is not None)

                    if our_ip is not None and dns_ips is not None:
                        last_problem_time = None
                        if our_ip not in dns_ips:
                            log.info("External IP address changed to {ip}".format(ip=our_ip))
                            status = update_dns()
                            record_dyndns_update(client, status)
                            record_ip_out_of_sync(client, ok=False)
                        else:
                            record_ip_out_of_sync(client, ok=True)

                    time.sleep(UPDATE_INTERVAL)

                status = update_dns()
                publish_status(client, our_ip, status)
                time.sleep(UPDATE_INTERVAL)

        except KeyboardInterrupt:
            log.info("Interrupted... shutting down")

        except Exception as e:
            log.error(str(e))
            client.publish(MQTT_BASE_TOPIC + "/status", payload="offline", retain=True).wait_for_publish()
            log.info("MQTT: disconnecting")
            client.loop_stop()
            client.disconnect()


# Press the green button in the gutter to run the script.
if __name__ == '__main__':
    # setup logging
    log = logging.getLogger()
    handler = logging.handlers.TimedRotatingFileHandler(LOG_FILENAME, when='midnight', backupCount=7)
    formatter = logging.Formatter('{asctime} {levelname:8s} {message}', style='{')

    handler.setFormatter(formatter)
    log.addHandler(handler)
    log.setLevel(logging.DEBUG)

    log.info("+=========================+")
    log.info("|       Starting up       |")
    log.info("+=========================+")

    update()

