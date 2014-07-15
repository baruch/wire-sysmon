#pragma pack(1)
struct msg_init {
	uint32_t version;
	uint32_t random;
	uint16_t port;
};

struct msg_result {
	uint64_t nsec;
};

struct msg_udp {
	uint32_t version;
	uint32_t random;
	uint32_t id;
	char padding[512 - sizeof(uint32_t)*3];
};
#pragma pack()
