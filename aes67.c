/*
 *  AES67 Soundcard
 *
 */
#include <linux/init.h>
#include <linux/slab.h>
#include <linux/platform_device.h>
#include <sound/core.h>
#include <sound/initval.h>
#include <linux/module.h>
#include <sound/pcm.h>
#include <net/sock.h>
#include <linux/udp.h>
#include <linux/kfifo.h>
#include <linux/kernel.h>
#include "aes67.h"


MODULE_AUTHOR("Stefan Neufeldt <stefan.neufeldt@gmail.com>");
MODULE_DESCRIPTION("A virtual AES67 based ALSA-audio driver which can receive and send RTP-audio packets in the local Network");
MODULE_LICENSE("GPL");
MODULE_SUPPORTED_DEVICE("{{ALSA,AES67 soundcard}}");

static int index[SNDRV_CARDS] = SNDRV_DEFAULT_IDX;
static char *id[SNDRV_CARDS] = SNDRV_DEFAULT_STR;
static bool enable[SNDRV_CARDS] = SNDRV_DEFAULT_ENABLE_PNP;
static int pcm_substreams[1] = {1};

static struct platform_device *aes67devices[SNDRV_CARDS];

static struct platform_driver aes67_driver = {
    .probe = aes67_probe,
    .remove = aes67_remove,
    .driver = {
        .name = SND_AES67_DRIVER,
        .owner = THIS_MODULE},
};

static struct snd_pcm_ops aes67_pcm_ops = {
    .open = aes67_open,
    .close = aes67_close,
    .ioctl = snd_pcm_lib_ioctl,
    .hw_params = aes67_hw_params,
    .hw_free = aes67_hw_free,
    .prepare = aes67_prepare,
    .trigger = aes67_trigger,
    .pointer = aes67_pointer,
};

static struct snd_pcm_hardware aes67_hw = {
    .info = SNDRV_PCM_INFO_INTERLEAVED | SNDRV_PCM_INFO_MMAP | SNDRV_PCM_INFO_MMAP_VALID,
    .formats = SNDRV_PCM_FMTBIT_S16_BE | SNDRV_PCM_FMTBIT_S24_BE,
    .rates = SNDRV_PCM_RATE_44100 | SNDRV_PCM_RATE_48000,
    .rate_min = 44100,
    .rate_max = 48000,
    .channels_min = 1,
    .channels_max = 2,
    .buffer_bytes_max = MAX_BUFFER,
    .period_bytes_min = 48,
    .period_bytes_max = 1024 * 1024,
    .periods_min = 1,
    .periods_max = 1024,
};

static void kernellog(int level, char *fmt, ...)
{
        va_list args;
        va_start(args, fmt);

        switch (level)
        {
        case LOGLEVEL_EMERG:
                vprintk(fmt, args);
                break;
        case LOGLEVEL_ALERT:
                vprintk(fmt, args);
                break;
        case LOGLEVEL_CRIT:
                vprintk(fmt, args);
                break;
        case LOGLEVEL_ERR:
                vprintk(fmt, args);
                break;
        case LOGLEVEL_WARNING:
                vprintk(fmt, args);
                break;
        case LOGLEVEL_NOTICE:
                vprintk(fmt, args);
                break;
#ifdef DEBUG_MESSAGES
        case LOGLEVEL_INFO:
                vprintk(fmt, args);
                break;
        case LOGLEVEL_DEBUG:
                vprintk(fmt, args);
                break;
#else
        default:
                vprintk(fmt, args);
                break;
#endif
        }

        va_end(args);
}

static void aes67_pcm_free(struct snd_pcm *pcm)
{
        struct aes67card *aes67card = snd_pcm_chip(pcm);
        destroy_workqueue(aes67card->wq);
}

static int aes67_pcm_new(struct aes67card *aes67card, int device, int substreams)
{
        int err = 0;
        struct snd_pcm *pcm;

        err = snd_pcm_new(aes67card->card, "AES67 PCM", device,
                          substreams, substreams, &pcm);
        if (err < 0) {
                kernellog(LOGLEVEL_ERR, "aes67_pcm_new: snd_pcm_new failed");
                return err;
        }

        snd_pcm_set_ops(pcm, SNDRV_PCM_STREAM_PLAYBACK, &aes67_pcm_ops);
        snd_pcm_set_ops(pcm, SNDRV_PCM_STREAM_CAPTURE, &aes67_pcm_ops);

        pcm->private_data = aes67card;
        pcm->private_free = aes67_pcm_free;
        pcm->info_flags = 0;
        strcpy(pcm->name, "AES67 PCM");

        aes67card->wq = create_workqueue(AES67_WQ);
        if (aes67card->wq == NULL) {
                kernellog(LOGLEVEL_ERR, "aes67_create_workqueue failed");
                return -ENOMEM;
        }

        snd_pcm_lib_preallocate_pages_for_all(pcm,
                                              SNDRV_DMA_TYPE_CONTINUOUS,
                                              snd_dma_continuous_data(GFP_KERNEL),
                                              MAX_BUFFER, MAX_BUFFER);
        if (err < 0) {
                kernellog(LOGLEVEL_ERR, "aes67_pcm_new: snd_pcm_lib_preallocate_pages_for_all failed");
                return err;
        }
        aes67card->pcm[device] = pcm;
        return 0;
}

static int joinMulticast(struct socketdata *socketdata)
{
        int err;
        if (socketdata == NULL) {
                kernellog(LOGLEVEL_ERR, "aes67_join_multicast: Socketdata NULL");
                return -EFAULT;
        }
        err = kernel_setsockopt(socketdata->sock, IPPROTO_IP, IP_ADD_MEMBERSHIP, (char *)&socketdata->mreq, sizeof(socketdata->mreq));
        if (err < 0) {
                kernellog(LOGLEVEL_ERR, "aes67_join_multicast: Could not set socketopt IP_ADD_MEMBERSHIP: %d", err);
                socketdata->is_multicast_adress = false;
                return err;
        }
        socketdata->is_multicast_adress = true;
        return 0;
}

static int leaveMulticast(struct socketdata *socketdata)
{
        int err;
        err = kernel_setsockopt(socketdata->sock, IPPROTO_IP, IP_DROP_MEMBERSHIP, (char *)&socketdata->mreq, sizeof(socketdata->mreq));
        if (err < 0) {
                kernellog(LOGLEVEL_ERR, "aes67_leave_multicast: Could not set socketopt IP_DROP_MEMBERSHIP: %d", err);
        }
        else {
                socketdata->is_multicast_adress = false;
        }
        return err;
}

static int aes67_socket_init(struct socketdata *socketdata, unsigned int ip_adress, unsigned int ip_port)
{
        int err;
        if (socketdata == NULL) {
                return -EFAULT;
        }

        socketdata->sequence_number = 0;
        socketdata->timestamp = 0;

        err = sock_create_kern(&init_net, AF_INET, SOCK_DGRAM, IPPROTO_UDP, &socketdata->sock);
        if (err < 0) {
                kernellog(LOGLEVEL_ERR, "aes67-debug:CREATE SOCKET ERROR");
                return err;
        }
        memset(&socketdata->to, 0, sizeof(socketdata->to));
        socketdata->to.sin_family = AF_INET;
        socketdata->to.sin_port = htons(ip_port);
        socketdata->to.sin_addr.s_addr = ip_adress;
        memset(&socketdata->mreq, 0, sizeof(socketdata->mreq));
        socketdata->mreq.imr_multiaddr = socketdata->to.sin_addr;
        socketdata->mreq.imr_address.s_addr = htonl(INADDR_ANY);
        socketdata->to.sin_addr = socketdata->mreq.imr_multiaddr;

        socketdata->sock->ops->bind(socketdata->sock, (struct sockaddr *)&socketdata->to, sizeof(socketdata->to));

        socketdata->is_multicast_adress = false;
        // Check if IP-Adress is Multicast
        if ((ip_adress & 0x000000F0) == 0x000000E0) {
                err = joinMulticast(socketdata);
                if (err < 0) {
                        kernellog(LOGLEVEL_ERR, "aes67_joinMulticast failed");
                        return err;
                }
        }
        return 0;
}

// returns the amount of data that has received
static int udp_receive(struct socket *sock, struct msghdr *header, void *buff, size_t size_buff)
{
        struct kvec vec;
        mm_segment_t oldmm;
        int res;
        vec.iov_len = size_buff;
        vec.iov_base = buff;
        oldmm = get_fs();
        set_fs(KERNEL_DS);
        // MSG_DONTWAIT: nonblocking operation: as soon as the packet is read, the call returns
        // MSG_WAITALL: blocks until it does not receive size_buff bytes OR the SO_RCVTIMEO expires.
        res = kernel_recvmsg(sock, header, &vec, 1, size_buff, MSG_DONTWAIT);
        set_fs(oldmm);
        return res;
}

static int socket_receive(struct socket *sock, struct sockaddr_in *addr, unsigned char *buf, int len)
{
        int size = 0;
        struct msghdr msg;
        struct iovec iov;
        if (sock->sk == NULL)
                return 0;
        iov.iov_base = buf;
        iov.iov_len = len;
        msg.msg_flags = 0;
        msg.msg_name = addr;
        msg.msg_namelen = sizeof(*addr);
        msg.msg_control = NULL;
        msg.msg_controllen = 0;
        iov_iter_init(&msg.msg_iter, READ, &iov, 1, len);
        msg.msg_control = NULL;
        size = udp_receive(sock, &msg, buf, len);
        return size;
}

static int aes67_receive_data(struct socketdata *socketdata)
{
        int size;
        size = 0;
        memset(socketdata->buf, 0, socketdata->packet_size);
        size = socket_receive(socketdata->sock, &socketdata->to, (unsigned char *)socketdata->buf, socketdata->packet_size);
        return size;
}

static int socket_send(struct socket *sock, struct sockaddr_in *addr, unsigned char *buf, int len)
{
        struct kvec vec;
        struct msghdr msg;
        vec.iov_base = buf;
        vec.iov_len = len;
        memset(&msg, 0x00, sizeof(msg));
        msg.msg_name = addr;
        msg.msg_namelen = sizeof(*addr);
        msg.msg_flags = MSG_DONTWAIT | MSG_NOSIGNAL;
        return kernel_sendmsg(sock, &msg, &vec, 1, len);
}

static int aes67_send_data(struct socketdata *socketdata)
{
        int err = 0;
        err = socket_send(socketdata->sock, &socketdata->to, (unsigned char *)socketdata->buf, socketdata->packet_size);
        return err;
}

static void aes67_prepare_rtp_packet(unsigned char *buf, int bufsize, struct kfifo *payload, struct socketdata *socketdata, struct streaminfo *streaminfo)
{
        unsigned int payload_size = streaminfo->payload_size;
        unsigned short *sequenzeNumber = &socketdata->sequence_number;
        unsigned int *timestamp = &socketdata->timestamp;
        if (bufsize < payload_size + UDP_HEADER_SIZE) {
                kernellog(LOGLEVEL_ERR, "bufsize is too small for this payloadSize");
                return;
        }
        if (kfifo_len(payload) < payload_size) {
                kernellog(LOGLEVEL_ERR, "payloadbuffer has not enough data for this payloadSize");
                return;
        }
        memset(buf, 0, bufsize);
        *buf = 0x80;
        buf++;
        *buf = 0x62;
        buf++;
        *buf = (*sequenzeNumber >> 8) & 0xff; //2-Byte Sequence Number
        buf++;
        *buf = *sequenzeNumber & 0xff; //2-Byte Sequence Number
        buf++;
        *buf = (*timestamp >> 24) & 0xff; //4-Byte Timestamp
        buf++;
        *buf = (*timestamp >> 16) & 0xff; //4-Byte Timestamp
        buf++;
        *buf = (*timestamp >> 8) & 0xff; //4-Byte Timestamp
        buf++;
        *buf = *timestamp & 0xff; //4-Byte Timestamp
        buf++;
        *buf = 0x00; //4-Byte Source identifier
        buf++;
        *buf = 0x00; //4-Byte Source identifier
        buf++;
        *buf = 0x00; //4-Byte Source identifier
        buf++;
        *buf = 0x00; //4-Byte Source identifier
        buf++;
        kfifo_out(payload, buf, payload_size);
        *sequenzeNumber += 1;
        *timestamp += (payload_size / streaminfo->pcm_bits / streaminfo->pcm_channels);
        return;
}

static unsigned int calculateBufferFrames(struct streaminfo *streaminfo)
{
        unsigned int last_pos;
        unsigned long delta;
        delta = jiffies - streaminfo->last_Timer_Ts; // Zeitdifferenz zwischen Jetzt und Last-Timestamp in Jiffies
        if (!delta) {
                return 0;
        }
        streaminfo->last_Timer_Ts += delta;                                // Aktualisieren der Timestamp-Variable in Jiffies
        last_pos = jiffies_to_msecs(streaminfo->timerVal) / 1000;          // Letzte Interrupt-Position in Sekunden // last_pos = timer_val in jiffies
        streaminfo->timerVal += delta * streaminfo->pcm_bps;               // timerVal += delta(jiffes) * bitsPerSecond =
        return (jiffies_to_msecs(streaminfo->timerVal) / 1000 - last_pos); //
}

static void write_fifo_buffer_from_pcm(struct streaminfo *streaminfo, unsigned int availableSpace)
{
        struct snd_pcm_substream *substream = streaminfo->substream;
        struct snd_pcm_runtime *runtime = substream->runtime;
        unsigned int fillSize, writtenBytes;
        writtenBytes = 0;
        while (writtenBytes < availableSpace) {
                fillSize = availableSpace - writtenBytes;
                if (streaminfo->buf_pos + fillSize > streaminfo->pcm_buffer_size) {                                                                     //Abfrage, ob das dma-area überschritten würde
                        fillSize = streaminfo->pcm_buffer_size - streaminfo->buf_pos; // Wenn ja, dann reduziere angefrage Bytes, sodass die dma_area bis zum Ende beschrieben wird
                }
                if (kfifo_avail(streaminfo->fifo_buffer) < fillSize) {
                        fillSize = kfifo_avail(streaminfo->fifo_buffer);
                }
                if (fillSize == 0) {
                        break;
                }
                writtenBytes += kfifo_in(streaminfo->fifo_buffer, (runtime->dma_area + streaminfo->buf_pos), fillSize);
                streaminfo->buf_pos += fillSize;
                streaminfo->buf_pos %= streaminfo->pcm_buffer_size;
                if (streaminfo->buf_pos == streaminfo->pcm_buffer_size) {
                        streaminfo->buf_pos = 0;
                }
        }
        if (streaminfo->timerVal >= streaminfo->period_size_frac) {
                streaminfo->timerVal &= streaminfo->period_size_frac;
                streaminfo->period_update_pending = 1;
        }
}

static void write_pcm_from_fifo_buffer(struct streaminfo *streaminfo, unsigned int availableSpace)
{
        struct snd_pcm_substream *substream = streaminfo->substream;
        struct snd_pcm_runtime *runtime = substream->runtime;
        unsigned int fillSize, writtenBytes;
        writtenBytes = 0;
        while (writtenBytes < availableSpace) {
                fillSize = availableSpace - writtenBytes;
                if (streaminfo->buf_pos + fillSize > streaminfo->pcm_buffer_size) {                                                                     //Abfrage, ob das dma-area überschritten würde
                        fillSize = streaminfo->pcm_buffer_size - streaminfo->buf_pos; // Wenn ja, dann reduziere angefrage Bytes, sodass die dma_area bis zum Ende beschrieben wird
                }
                if (fillSize > kfifo_len(streaminfo->fifo_buffer)) {
                        fillSize = kfifo_len(streaminfo->fifo_buffer);
                }
                if (fillSize == 0) {
                        break;
                }
                writtenBytes += kfifo_out(streaminfo->fifo_buffer, (runtime->dma_area + streaminfo->buf_pos), fillSize);
                streaminfo->buf_pos += fillSize;
                streaminfo->buf_pos %= streaminfo->pcm_buffer_size;
                if (streaminfo->buf_pos == streaminfo->pcm_buffer_size) {
                        streaminfo->buf_pos = 0;
                }
        }
        if (streaminfo->timerVal >= streaminfo->period_size_frac) {
                streaminfo->timerVal &= streaminfo->period_size_frac;
                streaminfo->period_update_pending = 1;
        }
}

static void aes67_update_fifo_buffer(struct streaminfo *streaminfo)
{
        unsigned int availableSpace;
        if (!streaminfo->running) {
                return;
        }
        availableSpace = calculateBufferFrames(streaminfo);
        if (!availableSpace) {
                return;
        }
        write_fifo_buffer_from_pcm(streaminfo, availableSpace);
        return;
}

static void aes67_update_pcm_buffer(struct streaminfo *streaminfo)
{
        unsigned int count;
        if (!streaminfo->running) {
                return;
        }
        count = calculateBufferFrames(streaminfo);
        if (!count) {
                return;
        }
        write_pcm_from_fifo_buffer(streaminfo, count);
}

static void aes67_timer_start(struct streaminfo *streaminfo)
{
        unsigned long tick;
        tick = streaminfo->period_size_frac - streaminfo->timerVal;
        tick = (tick + streaminfo->pcm_bps - 1) / streaminfo->pcm_bps;
        streaminfo->timer.expires = jiffies + tick;
        add_timer(&streaminfo->timer);
}

static void aes67_timer_stop(struct streaminfo *streaminfo)
{
        del_timer(&streaminfo->timer);
}

/* 
 * Timer-Callback-Function for Receive-Function
*/
static void aes67_timer_function_receive(struct timer_list *t)
{
        struct streaminfo *streaminfo = from_timer(streaminfo, t, timer);
        struct snd_pcm_substream *substream = streaminfo->substream;
        if (!streaminfo->running) {
                return;
        }
        aes67_update_pcm_buffer(streaminfo);
        aes67_timer_start(streaminfo);
        if (streaminfo->period_update_pending) {
                streaminfo->period_update_pending = 0;
                if (streaminfo->running) {
                        snd_pcm_period_elapsed(substream);
                }
        }
        return;
}
/* 
 * Timer-Callback-Function for Transmit-Function
*/
static void aes67_timer_function_transmit(struct timer_list *t)
{
        struct streaminfo *streaminfo = from_timer(streaminfo, t, timer);
        struct snd_pcm_substream *substream = streaminfo->substream;
        if (!streaminfo->running) {
                return;
        }
        aes67_update_fifo_buffer(streaminfo);
        aes67_timer_start(streaminfo);
        if (streaminfo->period_update_pending) {
                streaminfo->period_update_pending = 0;
                if (streaminfo->running) {
                        snd_pcm_period_elapsed(substream);
                }
        }
        return;
}

static void aes67Fillfifo_buffer(struct aes67card *aes67card)
{
        int size = 0;
        struct streaminfo *streaminfo = aes67card->rx;
        do {
                if (kfifo_avail(streaminfo->fifo_buffer) < streaminfo->payload_size) {
                        break;
                } //fifo_Buffer full
                size = aes67_receive_data(&aes67card->rx->socketdata);
                if (size > 0) {
                        size -= UDP_HEADER_SIZE;
                        kfifo_in(streaminfo->fifo_buffer, (aes67card->rx->socketdata.buf + UDP_HEADER_SIZE), size);
                }
        } while (size > 0);
        return;
}

static void aes67WqFn(struct work_struct *work)
{
        struct workdata *wd = (struct workdata *)work;
        struct aes67card *aes67card = wd->aescard;
        struct streaminfo *streaminfo;
        if (wd == NULL) {
                return;
        }
        if (wd->delayed_work_id == AES67_RECEIVE_WORK) {
                streaminfo = aes67card->rx;
                if (streaminfo == NULL) {
                        kernellog(LOGLEVEL_ERR, "aes67-debug: aes67WqFn: streaminfo is NULL");
                        return;
                }
                if (!aes67card->rx->running) {
                        return;
                }
                if (streaminfo->fifo_buffer == NULL) {
                        kernellog(LOGLEVEL_ERR, "aes67-debug: aes67WqFn: fifo_buffer is NULL");
                        return;
                }
                aes67Fillfifo_buffer(aes67card);
                queue_delayed_work(aes67card->wq, (struct delayed_work *)aes67card->rx->workdata, 1);
        }
        else if (wd->delayed_work_id == AES67_TRANSMIT_WORK)
        {
                streaminfo = aes67card->tx;
                if (!aes67card->tx->running) {
                        return;
                }
                if (streaminfo == NULL) {
                        kernellog(LOGLEVEL_ERR, "aes67-debug: aes67WqFn: streaminfo is NULL");
                        return;
                }
                if (streaminfo->fifo_buffer == NULL) {
                        kernellog(LOGLEVEL_ERR, "aes67-debug: aes67WqFn: fifo_buffer is NULL");
                        return;
                }
                while (kfifo_len(streaminfo->fifo_buffer) >= streaminfo->payload_size) {
                        aes67_prepare_rtp_packet(streaminfo->socketdata.buf, streaminfo->socketdata.packet_size, streaminfo->fifo_buffer, &streaminfo->socketdata, streaminfo);
                        aes67_send_data(&streaminfo->socketdata);
                }
                queue_delayed_work(aes67card->wq, (struct delayed_work *)aes67card->tx->workdata, 1);
        }
        else {
                return;
        }
        return;
}

static int aes67_init_queue_work(struct workdata **wd, int workId, struct aes67card *aes67card)
{
        if (aes67card->wq == NULL) {
                kernellog(LOGLEVEL_ERR, "aes67-debug: init_and_queue_work workqueue is empty");
                return -EFAULT;
        }
        (*wd) = (struct workdata *)kmalloc(sizeof(**wd), GFP_KERNEL);
        if ((*wd) == NULL) {
                kernellog(LOGLEVEL_ERR, "aes67-debug: init_and_queue_work workdata allocation failed for work %d", workId);
                return -ENOMEM;
        }
        (*wd)->aescard = aes67card;
        (*wd)->delayed_work_id = workId;
        INIT_DELAYED_WORK((struct delayed_work *)(*wd), aes67WqFn);
        return 0;
}

static inline void aes67_free_queue_work(struct workdata **wd)
{
        if ((*wd)) {
                cancel_delayed_work_sync((struct delayed_work *)(*wd));
                kfree((*wd));
                *wd = NULL;
        }
}

static inline int aes67_init_fifo(struct kfifo **kfifo_input)
{
        int err = 0;
        (*kfifo_input) = (struct kfifo *)kmalloc(sizeof(**kfifo_input), GFP_KERNEL);
        if ((*kfifo_input) == NULL) {
                kernellog(LOGLEVEL_ERR, "aes67_kfifo-kmalloc failed");
                return -ENOMEM;
        }
        err = kfifo_alloc((*kfifo_input), AUDIO_BUFFER_SIZE, GFP_KERNEL);
        return err;
}

static inline void aes67_free_fifo(struct kfifo **kfifo_input)
{
        if ((*kfifo_input)) {
                kfifo_free((*kfifo_input));
                kfree((*kfifo_input));
        }
}

static inline void streaminfo_runtime_free(struct snd_pcm_runtime *runtime)
{
        struct streaminfo *streaminfo = runtime->private_data;
        kfree(streaminfo);
        streaminfo = NULL;
        return;
}

static int aes67_open(struct snd_pcm_substream *substream)
{
        struct aes67card *aes67card = snd_pcm_substream_chip(substream);
        struct snd_pcm_runtime *runtime = substream->runtime;
        struct streaminfo *streaminfo;
        int err = 0;
        if (mutex_lock_interruptible(&aes67card->lock)) {
                return -EINTR;
        }
        streaminfo = kzalloc(sizeof(*streaminfo), GFP_KERNEL);
        if (!streaminfo) {
                err = -ENOMEM;
                goto unlock;
        }
        streaminfo->aescard = aes67card;
        streaminfo->substream = substream;
        runtime->hw = aes67_hw;
        runtime->private_data = streaminfo;
        runtime->private_free = streaminfo_runtime_free;

        if (substream->stream == SNDRV_PCM_STREAM_PLAYBACK) {
                aes67card->tx = streaminfo;
        } else if (substream->stream == SNDRV_PCM_STREAM_CAPTURE) {
                aes67card->rx = streaminfo;
        } else {return -ENXIO;}
        unlock:
        mutex_unlock(&aes67card->lock);
        return err;
}

static int aes67_close(struct snd_pcm_substream *substream)
{
        struct aes67card *aes67card = snd_pcm_substream_chip(substream);
        if (mutex_lock_interruptible(&aes67card->lock)) {
                return -EINTR;
        }
        substream->private_data = NULL;
        mutex_unlock(&aes67card->lock);
        return 0;
}

static int aes67_hw_params(struct snd_pcm_substream *substream, struct snd_pcm_hw_params *hw_params)
{
        struct aes67card *aes67card = snd_pcm_substream_chip(substream);
        struct streaminfo *streaminfo = (struct streaminfo*) substream->runtime->private_data;
        int ip_adress, ip_port, worktype;
        int err = 0;
        void (*timer_callback_function) (struct timer_list*);
        if (mutex_lock_interruptible(&aes67card->lock)) {
                err = -EINTR;
                goto unlock;
        }
        if (substream->stream == SNDRV_PCM_STREAM_PLAYBACK) {
                ip_adress = aes67card->destination_ip_adress;
                ip_port = aes67card->destination_ip_port;
                worktype = AES67_TRANSMIT_WORK;
                timer_callback_function = &aes67_timer_function_transmit;
        } else if (substream->stream == SNDRV_PCM_STREAM_CAPTURE) {
                ip_adress = aes67card->source_ip_adress;
                ip_port = aes67card->source_ip_port;
                worktype = AES67_RECEIVE_WORK;
                timer_callback_function = &aes67_timer_function_receive;
        } else {
                err =  -ENXIO;
                goto unlock;
        }
        
        err = aes67_socket_init(&streaminfo->socketdata, ip_adress, ip_port);
        if (err < 0) {
                kernellog(LOGLEVEL_ERR, "aes67_snd_card_socket_init failed");
                goto unlock;
        }
        
        if (!streaminfo->workdata) {
                err = aes67_init_queue_work(&streaminfo->workdata, worktype, aes67card);
                if (err) {
                        goto unlock;
                }
        }
        err = aes67_init_fifo(&streaminfo->fifo_buffer);
        if (err) {
                kernellog(LOGLEVEL_ERR, "aes67_init_fifo failed %d", err);
                goto unlock;
        }
        timer_setup(&streaminfo->timer, timer_callback_function, 0);
        err = snd_pcm_lib_malloc_pages(substream, params_buffer_bytes(hw_params));
        unlock:
        mutex_unlock(&aes67card->lock);
        return err;
}

static int aes67_hw_free(struct snd_pcm_substream *substream)
{
        struct aes67card *aes67card = snd_pcm_substream_chip(substream);
        struct streaminfo *streaminfo = (struct streaminfo*) substream->runtime->private_data;
        int err = 0;
        if (mutex_lock_interruptible(&aes67card->lock)) {
                err = -EINTR;
                goto unlock;
        }
        del_timer_sync(&streaminfo->timer);
        aes67_free_queue_work(&streaminfo->workdata);
        if (streaminfo->socketdata.is_multicast_adress) {
                err = leaveMulticast(&streaminfo->socketdata);
        }
        sock_release(streaminfo->socketdata.sock);
        if (streaminfo->socketdata.buf) {
                kfree(streaminfo->socketdata.buf);
                streaminfo->socketdata.buf = NULL;
        }
        aes67_free_fifo(&streaminfo->fifo_buffer);
        err = snd_pcm_lib_free_pages(substream);
        unlock:
        mutex_unlock(&aes67card->lock);
        return err;
}

static int aes67_prepare(struct snd_pcm_substream *substream)
{
        struct aes67card *aes67card = snd_pcm_substream_chip(substream);
        struct snd_pcm_runtime *runtime = substream->runtime;
        struct streaminfo *streaminfo = (struct streaminfo*) substream->runtime->private_data;
        unsigned int bps, packet_samples_per_channel;
        int err = 0;
        if (substream->stream == SNDRV_PCM_STREAM_PLAYBACK) {
                packet_samples_per_channel = aes67card->destination_packet_samples_per_channel;
        } else if (substream->stream == SNDRV_PCM_STREAM_CAPTURE) {
                packet_samples_per_channel = aes67card->source_packet_samples_per_channel;
        } else {
                err =  -ENXIO;
                goto unlock;
        }
        streaminfo->buf_pos = 0;
        streaminfo->pcm_buffer_size = frames_to_bytes(runtime, runtime->buffer_size);
        bps = runtime->rate * runtime->channels; // params requested by user app (arecord, audacity)
        bps *= snd_pcm_format_width(runtime->format);
        bps /= 8;
        if (bps <= 0) {
                kernellog(LOGLEVEL_ERR, "aes67-debug: wrong bps");
                err = -EINVAL;
                goto unlock;
        }
        if (mutex_lock_interruptible(&aes67card->lock)) {
                err = -EINTR;
                goto unlock;
        }
        streaminfo->pcm_bits = snd_pcm_format_width(runtime->format);
        streaminfo->pcm_channels = runtime->channels;
        streaminfo->payload_size = packet_samples_per_channel * streaminfo->pcm_channels * streaminfo->pcm_bits / 8;
        streaminfo->socketdata.packet_size = streaminfo->payload_size + UDP_HEADER_SIZE;
        if (!streaminfo->socketdata.buf) {
                streaminfo->socketdata.buf = kzalloc(streaminfo->socketdata.packet_size, GFP_KERNEL);
                if (!streaminfo->socketdata.buf) {
                        err = -ENOMEM;
                        goto unlock;
                }
        }
        if (!streaminfo->running) {
                streaminfo->buf_pos = 0;
                streaminfo->period_update_pending = 0;
        }
        if (!(streaminfo->valid & ~(1 << substream->stream))) {
                streaminfo->pcm_bps = bps;
                streaminfo->pcm_period_size = frames_to_bytes(runtime, runtime->period_size);
                streaminfo->period_size_frac = msecs_to_jiffies(streaminfo->pcm_period_size * 1000);
        }
        streaminfo->valid |= 1 << substream->stream;
        unlock:
        mutex_unlock(&aes67card->lock);
        return err;
}

static int aes67_trigger(struct snd_pcm_substream *substream, int cmd)
{
        int ret = 0;
        struct aes67card *aes67card = snd_pcm_substream_chip(substream);
        struct streaminfo *streaminfo = (struct streaminfo*) substream->runtime->private_data;
        switch (cmd) {
        case SNDRV_PCM_TRIGGER_START:
                if (!streaminfo->running) {
                        queue_delayed_work(aes67card->wq, (struct delayed_work *)streaminfo->workdata, 1);
                        streaminfo->last_Timer_Ts = jiffies;
                        aes67_timer_start(streaminfo);
                }
                streaminfo->running |= (1 << substream->stream);
                break;
        case SNDRV_PCM_TRIGGER_STOP:
                streaminfo->running &= ~(1 << substream->stream);
                if (!streaminfo->running) {
                        aes67_timer_stop(streaminfo);
                        cancel_delayed_work((struct delayed_work *)streaminfo->workdata);
                }
                break;
        default:
                kernellog(LOGLEVEL_NOTICE, "aes67_playback_trigger: Unknown");
                ret = -EINVAL;
        }
        return ret;
}

static snd_pcm_uframes_t aes67_pointer(struct snd_pcm_substream *substream)
{
        struct snd_pcm_runtime *runtime = substream->runtime;
        struct streaminfo *streaminfo = (struct streaminfo*) substream->runtime->private_data;
        if (substream->stream == SNDRV_PCM_STREAM_PLAYBACK) {
                aes67_update_fifo_buffer(streaminfo);
        } else if (substream->stream == SNDRV_PCM_STREAM_CAPTURE) {
                aes67_update_pcm_buffer(streaminfo);
        } else {
                return -ENXIO;
        }
        return bytes_to_frames(runtime, streaminfo->buf_pos);
}

//returns address in Network Byte Order
static inline unsigned int inet_addr(const char *str)
{
        int a, b, c, d;
        char arr[4];
        sscanf(str, "%d.%d.%d.%d", &a, &b, &c, &d);
        arr[0] = a;
        arr[1] = b;
        arr[2] = c;
        arr[3] = d;
        return *(unsigned int *)arr;
}

static ssize_t read_source_adress(struct device *dev, struct device_attribute *attr, char *buf)
{
        struct snd_card *card = dev_get_drvdata(dev);
        struct aes67card *aes67card = card->private_data;
        int len;
        len = sprintf(buf, "%pI4\n", &aes67card->source_ip_adress);
        if (len <= 0)
                dev_err(dev, "mydrv: Invalid sprintf len: %d\n", len);
        return len;
}

static ssize_t write_source_adress(struct device *dev, struct device_attribute *attr, const char *buf, size_t count)
{
        struct snd_card *card = dev_get_drvdata(dev);
        struct aes67card *aes67card = card->private_data;
        aes67card->source_ip_adress = inet_addr(buf);
        return count;
}

static ssize_t read_source_port(struct device *dev, struct device_attribute *attr, char *buf)
{
        struct snd_card *card = dev_get_drvdata(dev);
        struct aes67card *aes67card = card->private_data;
        int len;
        len = sprintf(buf, "%u\n", aes67card->source_ip_port);
        if (len <= 0)
                dev_err(dev, "aes67: Invalid sprintf len: %d\n", len);
        return len;
}

static ssize_t write_source_port(struct device *dev, struct device_attribute *attr, const char *buf, size_t count)
{
        struct snd_card *card = dev_get_drvdata(dev);
        struct aes67card *aes67card = card->private_data;
        kstrtouint(buf, 0, &aes67card->source_ip_port);
        return count;
}

static ssize_t read_destination_adress(struct device *dev, struct device_attribute *attr, char *buf)
{
        struct snd_card *card = dev_get_drvdata(dev);
        struct aes67card *aes67card = card->private_data;
        int len;
        len = sprintf(buf, "%pI4\n", &aes67card->destination_ip_adress);
        if (len <= 0)
                dev_err(dev, "aes67: Invalid sprintf len: %d\n", len);
        return len;
}

static ssize_t write_destination_adress(struct device *dev, struct device_attribute *attr, const char *buf, size_t count)
{
        struct snd_card *card = dev_get_drvdata(dev);
        struct aes67card *aes67card = card->private_data;
        aes67card->destination_ip_adress = inet_addr(buf);
        return count;
}

static ssize_t read_destination_port(struct device *dev, struct device_attribute *attr, char *buf)
{
        struct snd_card *card = dev_get_drvdata(dev);
        struct aes67card *aes67card = card->private_data;
        int len;
        len = sprintf(buf, "%u\n", aes67card->destination_ip_port);
        if (len <= 0)
                dev_err(dev, "aes67: Invalid sprintf len: %d\n", len);
        return len;
}

static ssize_t write_destination_port(struct device *dev, struct device_attribute *attr, const char *buf, size_t count)
{
        struct snd_card *card = dev_get_drvdata(dev);
        struct aes67card *aes67card = card->private_data;
        kstrtouint(buf, 0, &aes67card->destination_ip_port);
        return count;
}

static ssize_t read_source_packet_samples_per_channel(struct device *dev, struct device_attribute *attr, char *buf)
{
        struct snd_card *card = dev_get_drvdata(dev);
        struct aes67card *aes67card = card->private_data;
        int len;
        len = sprintf(buf, "%u\n", aes67card->source_packet_samples_per_channel);
        if (len <= 0)
                dev_err(dev, "aes67: Invalid sprintf len: %d\n", len);
        return len;
}

static ssize_t write_source_packet_samples_per_channel(struct device *dev, struct device_attribute *attr, const char *buf, size_t count)
{
        struct snd_card *card = dev_get_drvdata(dev);
        struct aes67card *aes67card = card->private_data;
        kstrtouint(buf, 0, &aes67card->source_packet_samples_per_channel);
        return count;
}

static ssize_t read_destination_packet_samples_per_channel(struct device *dev, struct device_attribute *attr, char *buf)
{
        struct snd_card *card = dev_get_drvdata(dev);
        struct aes67card *aes67card = card->private_data;
        int len;
        len = sprintf(buf, "%u\n", aes67card->destination_packet_samples_per_channel);
        if (len <= 0)
                dev_err(dev, "aes67: Invalid sprintf len: %d\n", len);
        return len;
}

static ssize_t write_destination_packet_samples_per_channel(struct device *dev, struct device_attribute *attr, const char *buf, size_t count)
{
        struct snd_card *card = dev_get_drvdata(dev);
        struct aes67card *aes67card = card->private_data;
        kstrtouint(buf, 0, &aes67card->destination_packet_samples_per_channel);
        return count;
}

static DEVICE_ATTR(source_ip, S_IRUGO | S_IWUSR, read_source_adress, write_source_adress);
static DEVICE_ATTR(source_port, S_IRUGO | S_IWUSR, read_source_port, write_source_port);
static DEVICE_ATTR(destination_ip, S_IRUGO | S_IWUSR, read_destination_adress, write_destination_adress);
static DEVICE_ATTR(destination_port, S_IRUGO | S_IWUSR, read_destination_port, write_destination_port);
static DEVICE_ATTR(source_packet_samples_per_channel, S_IRUGO | S_IWUSR, read_source_packet_samples_per_channel, write_source_packet_samples_per_channel);
static DEVICE_ATTR(destination_packet_samples_per_channel, S_IRUGO | S_IWUSR, read_destination_packet_samples_per_channel, write_destination_packet_samples_per_channel);

static struct attribute *aes67_attrs[] = {
    &dev_attr_source_ip.attr,
    &dev_attr_source_port.attr,
    &dev_attr_destination_ip.attr,
    &dev_attr_destination_port.attr,
    &dev_attr_source_packet_samples_per_channel.attr,
    &dev_attr_destination_packet_samples_per_channel.attr,
    NULL};
ATTRIBUTE_GROUPS(aes67);

static int aes67_probe(struct platform_device *devptr)
{
        struct snd_card *card;
        struct aes67card *aes67card;
        int dev = devptr->id;
        int err = 0;
        err = snd_card_new(&devptr->dev, index[dev], id[dev], THIS_MODULE,
                           sizeof(*aes67card), &card);
        if (err < 0) {
                kernellog(LOGLEVEL_ERR, "aes67_probe failed");
                return err;
        }

        aes67card = card->private_data;
        aes67card->card = card;
        mutex_init(&aes67card->lock);

        err = aes67_pcm_new(aes67card, 0, pcm_substreams[dev]);
        if (err < 0) {
                kernellog(LOGLEVEL_ERR, "Error at aes67_pcm_new");
                goto __nodev;
        }

        strcpy(card->driver, "AES67-Card-Driver");
        strcpy(card->shortname, "AES67-Soundcard");
        sprintf(card->longname, "AES67-Soundcard %i", dev + 1);

        err = snd_card_register(card);
        if (err < 0) {
                kernellog(LOGLEVEL_ERR, "aes67_snd_card_register failed");
                goto __nodev;
        }
        platform_set_drvdata(devptr, card);

        err = sysfs_create_group(&devptr->dev.kobj, &aes67_group);
        if (err) {
                kernellog(LOGLEVEL_ERR, "aes67_snd_card_register failed");
                goto __nodev;
        }

        aes67card->source_ip_adress = DEFAULT_IP;
        aes67card->source_ip_port = DEFAULT_PORT;
        aes67card->source_packet_samples_per_channel = DEFAULT_PACKET_SAMPLES_PER_CHANNEL;
        aes67card->destination_ip_adress = DEFAULT_IP;
        aes67card->destination_ip_port = DEFAULT_PORT;
        aes67card->destination_packet_samples_per_channel = DEFAULT_PACKET_SAMPLES_PER_CHANNEL;
        return 0;
__nodev:
        kernellog(LOGLEVEL_ERR, "aes67_probe Error err: %d", err);
        snd_card_free(card);
        return err;
}

static int aes67_remove(struct platform_device *devptr)
{
        sysfs_remove_group(&devptr->dev.kobj, &aes67_group);
        snd_card_free(platform_get_drvdata(devptr));
        return 0;
}

static void aes67_unregister_all(void)
{
        int i = 0;
        for (i = 0; i < ARRAY_SIZE(aes67devices); i++)
                platform_device_unregister(aes67devices[i]);
}

static int __init aes67_init(void)
{
        int i, err, cards, requestedCards;
        err = platform_driver_register(&aes67_driver);
        if (err < 0) {
                kernellog(LOGLEVEL_ERR, "aes67-debug:aes67_init reg err %d", err);
                return err;
        }
        cards = 0;
        requestedCards = NUMBER_OF_REQUESTED_CARDS;
        if (requestedCards > SNDRV_CARDS)
                requestedCards = SNDRV_CARDS;
        for (i = 0; i < requestedCards; i++) {
                struct platform_device *device;
                if (!enable[i])
                        continue;

                device = platform_device_register_simple(SND_AES67_DRIVER, i, NULL, 0);

                if (IS_ERR(device)) {
                        kernellog(LOGLEVEL_ERR, "aes67-debug:aes67_init regsimple err");
                        continue;
                }

                if (!platform_get_drvdata(device)) {
                        kernellog(LOGLEVEL_ERR, "aes67-debug:aes67_init getdrvdata err");
                        platform_device_unregister(device);
                        continue;
                }
                kernellog(LOGLEVEL_NOTICE, "aes67-debug:aes67_init platform_device_register_simple finished");
                aes67devices[i] = device;
                cards++;
        }
        if (!cards) {
#ifdef MODULE
                kernellog(LOGLEVEL_ERR, "aes67-debug:aes67_init No enabled, not found or device busy");
#endif
                aes67_unregister_all();
                return -ENODEV;
        }
        return 0;
}

static void __exit aes67_exit(void)
{
        aes67_unregister_all();
        platform_driver_unregister(&aes67_driver);
}

module_init(aes67_init)
module_exit(aes67_exit)