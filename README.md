# Debug over Bluetooth GATT Service

## Overview

This library provides various debug functions over Generic Attribute Service (GATT) Bluetooth Low-Energy (BLE) service.

The service is designed to be usable with any generic BLE mobile app that supports GATT, e.g. BLE Scanner ([Android](https://play.google.com/store/apps/details?id=com.macdom.ble.blescanner), [iOS](https://itunes.apple.com/us/app/ble-scanner-4-0/id1221763603)).

*Warning:* At present, this service is not secured in any way and anyone within range of a device that has this service enabled will be able to read and change its configuration. In its current form it is only intended for initial provisioning and should be turned off immediately after initial setup. See example provisioning process below.

## Attribute description

The service UUID is `5f6d4f53-5f44-4247-5f53-56435f49445f`, which is a representation of a 16-byte string `_mOS_DBG_SVC_ID_`.

At present, only one characteristic is defined:

* `306d4f53-5f44-4247-5f6c-6f675f5f5f30 (0mOS_DBG_log___0)` - a read/notify attribute that returns last debug log record when read. It also sends notifications with log messages as they are printed.
   * _Note 1_: Reading large messages is supported, but for notificatiosn to be useful you will most likely want to set higher MTU.
   * _Note 2_: For internal reasons, currently a read is required for notifications to be sent. After this characteristic has been read at least once, the device will start sending notifications for that connection.
