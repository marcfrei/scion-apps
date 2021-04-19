#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include <sys/time.h>

#include "libdrkey.h"

struct delegation_secret {
	int64_t validity_not_before;
	int64_t validity_not_after;
	unsigned char key[16];
};

int main() {
	struct timeval tv;
	int r = gettimeofday(&tv, NULL);
	if (r != 0) {
		assert(r == -1);
		printf("Syscall gettimeofday failed.\n");
		exit(EXIT_FAILURE);
	}
	assert((INT64_MIN <= tv.tv_sec) && (tv.tv_sec <= INT64_MAX));
	int64_t t_now = tv.tv_sec;

	struct delegation_secret ds;
	char ds_buf[sizeof ds.validity_not_before + sizeof ds.validity_not_after + sizeof ds.key];
	memset(ds_buf, 0, sizeof ds_buf);

	GetDelegationSecret("127.0.0.1:30255", 0x0011ffaa00010d69, 0x0011ffaa00010e97, t_now, ds_buf);

	size_t i = 0;
	memcpy(&ds.validity_not_before, &ds_buf[i], sizeof ds.validity_not_before);
	i += sizeof ds.validity_not_before;
	memcpy(&ds.validity_not_after, &ds_buf[i], sizeof ds.validity_not_after);
	i += sizeof ds.validity_not_after;
	memcpy(&ds.key, &ds_buf[i], sizeof ds.key);

	printf("DS key = ");
	for (i = 0; i < sizeof ds.key; i++) {
		printf("%02x", ds.key[i]);
	}
	printf(", epoch = [");
	struct tm *gmt;
	gmt = gmtime((time_t *)&ds.validity_not_before);
	if (gmt != NULL) {
		printf("%04d-%02d-%02d'T'%02d:%02d:%02d'Z'",
			1900 + gmt->tm_year, 1 + gmt->tm_mon, gmt->tm_mday,
			gmt->tm_hour, gmt->tm_min, gmt->tm_sec);
	}
	printf(", ");
	gmt = gmtime((time_t *)&ds.validity_not_after);
	if (gmt != NULL) {
		printf("%04d-%02d-%02d'T'%02d:%02d:%02d'Z'",
			1900 + gmt->tm_year, 1 + gmt->tm_mon, gmt->tm_mday,
			gmt->tm_hour, gmt->tm_min, gmt->tm_sec);
	}
	printf("]\n");
}

/*
go build -o bin/example-hellodrkey ./_examples/hellodrkey/hellodrkey.go

go build -buildmode=c-archive -o bin/libdrkey.a ./_examples/hellodrkey/hellodrkey.go
cc -o bin/hellolibdrkey -Wall -Werror -I bin -L bin _examples/hellodrkey/hellolibdrkey.c -ldrkey -lpthread
cc -o bin/hellolibdrkey -Wall -Werror -I bin -L bin _examples/hellodrkey/hellolibdrkey.c -ldrkey -framework CoreFoundation -framework Security
*/
