#define SND_AES67_DRIVER "snd_aes67"
#define PORT 5004
#define DEFAULT_IP 2776647151
#define DEFAULT_PORT 5004
#define DEFAULT_PACKET_SAMPLES_PER_CHANNEL 48
#define UDP_HEADER_SIZE 12
/* fifo size in elements (bytes) */
#define AUDIO_BUFFER_SIZE 32768

#define NUMBER_OF_REQUESTED_CARDS 1
#define DEBUG_MESSAGES 1
#define MAX_BUFFER (2 * 192 * 1500)

#define AES67_RECEIVE_WORK       (0)
#define AES67_TRANSMIT_WORK       (1)
#define AES67_WQ "AES67WQ"

static int aes67_probe(struct platform_device *devptr);
static int aes67_remove(struct platform_device *devptr);
static void aes67_unregister_all(void);
static int __init aes67_init(void);
static void __exit aes67_exit(void);
static int aes67_open(struct snd_pcm_substream *substream);
static int aes67_close(struct snd_pcm_substream *substream);
static int aes67_hw_params(struct snd_pcm_substream *substream, struct snd_pcm_hw_params *params);
static int aes67_hw_free(struct snd_pcm_substream *substream);
static int aes67_prepare(struct snd_pcm_substream *substream);
static int aes67_trigger(struct snd_pcm_substream *substream, int cmd);
static snd_pcm_uframes_t aes67_pointer(struct snd_pcm_substream *substream);
static unsigned int inet_addr(const char *str);

struct workdata {
	struct delayed_work work;
	int delayed_work_id;
    struct aes67card *aescard;
};


struct socketdata {
    struct socket* sock;
    struct sockaddr_in to;
    struct ip_mreqn mreq;
    unsigned char *buf;
    unsigned int is_multicast_adress;
    unsigned short sequence_number;
    unsigned int timestamp;
    unsigned int packet_size;
};


struct streaminfo {
    /* flags */
    unsigned int running;       // Flag
	unsigned int valid;
    unsigned int period_update_pending :1;

    /* pcm stuff */
    struct snd_pcm_substream *substream;
	unsigned int pcm_buffer_size;
	unsigned int buf_pos;	/* position in buffer */	
    /* PCM parameters */
	unsigned int pcm_period_size;   //Größe des PCM-Substreams in Bytes
	unsigned int pcm_bps;		/* bytes per second */
    unsigned int pcm_bits;
    unsigned int pcm_channels;
    
    /* timer stuff  */ 
	unsigned int timerVal;     // IRQ-Interrupt-Pos in Sekunden
    unsigned int period_size_frac; // periode size in jiffies ticks
	unsigned long int last_Timer_Ts;  // last_jiffies
	struct timer_list timer;        // Timerstruct

    /* Ringbuffer for Audiodata */
    struct kfifo *fifo_buffer;
    struct socketdata socketdata;
    struct aes67card *aescard;
    struct workdata *workdata;

    unsigned int payload_size;
};

/* definition of the chip-specific record */
struct aes67card {
    struct snd_card *card;
    struct snd_pcm *pcm[1];
    struct streaminfo *tx;
    struct streaminfo *rx;
    struct workqueue_struct *wq;
    struct mutex lock;

    unsigned int destination_ip_adress;
    unsigned int destination_ip_port;
    unsigned int source_ip_adress;
    unsigned int source_ip_port;
    unsigned int source_packet_samples_per_channel;
    unsigned int destination_packet_samples_per_channel;
};
