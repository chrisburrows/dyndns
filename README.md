# duckdns

Simple python script to maintain an external IP address with DynamicDNS.

The script also maintains four sensors for Home Assistant via MQTT:

- an availability sensor to show if the script itself is running
- a sensor with the external IPv4 address
- a sensor for the state of the dynamic DNS name. This sensor has the HA device class of "problem" so indicates if there is an issue with updating the domain
- a sensor with the time the last problem occurred

Home Assistant auto-discovery is supported for these sensors.

The script can be configured by hacking the defaults, or using environment variables. The environment variables approach lends itself well to setting up the script as a systemd service on Linux and importing the configuration variables.
