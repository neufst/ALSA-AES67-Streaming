# ALSA-AES67-Streaming

A virtual AES67 based ALSA-audio driver which can receive and send RTP-audio packets in the local Network. At the moment without PTP-Support!

# Features

* Native virtual ALSA-Deivce driver without additional user space daemon
* support for 44,1 kHz and 48 kHz Samplerate
* support for 16 Bit and 24 Bit Sample depth
* definable Packet Size
* configurable IP-Settings
* configuration via Sysfs

# Installing and Testing

## Add the driver ressources and load module

1. Please copy aes67.c und aes67.h to linux/sound/drivers

2. Compile the Sourcefiles

        make

3. Load the Driver

        sudo insmod snd-aes67.ko

## Unload Modul

    sudo  rmmod snd-aes67.ko



# configure Settings via Sysfs

Show source IP-Address:
    
    cat /sys/devices/platform/snd_aes67.0/source_ip

Set source IP-Address:

    echo "123.123.123.123" | sudo tee -a /sys/devices/platform/snd_aes67.0/source_ip

Show source IP-Port:
    
    cat /sys/devices/platform/snd_aes67.0/source_port 
        
Set source IP-Port:

    echo "5004" | sudo tee -a /sys/devices/platform/snd_aes67.0/source_port 

Show source samples per channel:

    cat /sys/devices/platform/snd_aes67.0/source_packet_samples_per_channel

Set source samples per channel:

    echo "48" | sudo tee -a /sys/devices/platform/snd_aes67.0/source_packet_samples_per_channel

Show destination IP-Address: 

    cat /sys/devices/platform/snd_aes67.0/destination_ip
        
Set destination IP-Address:

    echo "123.123.123.123" | sudo tee -a /sys/devices/platform/snd_aes67.0/destination_ip

Show destination IP-Port:

    cat /sys/devices/platform/snd_aes67.0/destination_port
        
Set destination IP-Port:

    echo "5004" | sudo tee -a /sys/devices/platform/snd_aes67.0/destination_port

Show destination samples per channel:

    cat /sys/devices/platform/snd_aes67.0/destination_packet_samples_per_channel
        
Set destination samples per channel:
        
    echo "48" | sudo tee -a /sys/devices/platform/snd_aes67.0/destination_packet_samples_per_channel


