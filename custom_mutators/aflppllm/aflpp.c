#include "afl-fuzz.h"
#include <string.h>
#include "afl-mutations.h"
#include <hiredis/hiredis.h>

// host
#define REDIS_HOST "localhost"
#define REDIS_HOST_WIN "host.docker.internal"
#define REDIS_PORT 6379
#define REDIS_PASSWORD "password"

redisContext *c;

typedef struct my_mutator {
  afl_state_t *afl;
  u8          *buf;
  u32          buf_size;

} my_mutator_t;

my_mutator_t *afl_custom_init(afl_state_t *afl, unsigned int seed) {
  redisReply *reply;
  c = redisConnect(REDIS_HOST, REDIS_PORT);
  if (c != NULL && c->err) {
    printf("Error: %s \n", c->errstr);
    printf("Trying again with windows host: %s... \n", REDIS_HOST_WIN);
    redisFree(c);
    c = redisConnect(REDIS_HOST_WIN, REDIS_PORT);

    if (c != NULL && c->err) {
      printf("Error: %s \n", c->errstr);
      redisFree(c);
      c = NULL;
    } else {
      printf("Connected to Redis with Windows Host\n");
    }
  } else {
    printf("Connected to Redis with localhost.\n");
  }

  if (c != NULL && !c->err) {
    reply = redisCommand(c, "AUTH %s", REDIS_PASSWORD);
    if (reply == NULL) {
      printf("Error: %s\n", c->errstr);
      redisFree(c);
      c = NULL;
    }
    printf("Connected with correct credential. \n");
    freeReplyObject(reply);
  }

  (void)seed;

  my_mutator_t *data = calloc(1, sizeof(my_mutator_t));
  if (!data) {
    perror("afl_custom_init alloc");
    return NULL;
  }

  if ((data->buf = malloc(MAX_FILE)) == NULL) {
    perror("afl_custom_init alloc");
    return NULL;

  } else {
    data->buf_size = MAX_FILE;
  }

  data->afl = afl;

  return data;
}

/* here we run the AFL++ mutator, which is the best! */

size_t afl_custom_fuzz(my_mutator_t *data, uint8_t *buf, size_t buf_size,
                       u8 **out_buf, uint8_t *add_buf, size_t add_buf_size,
                       size_t max_size) {
  if (max_size > data->buf_size) {
    u8 *ptr = realloc(data->buf, max_size);

    if (!ptr) {
      return 0;

    } else {
      data->buf = ptr;
      data->buf_size = max_size;
    }
  }

  redisReply *reply;
  if (c) {
    uint8_t raw_data[] = {0x01, 0x02, 0x03, 0x04, 0xFF};
    size_t  raw_data_len = sizeof(raw_data);
    reply =
        (redisReply *)redisCommand(c, "RPUSH C2P %b", raw_data, raw_data_len);
    if (reply == NULL) { printf("Error sending data: %s\n", c->errstr); }
    freeReplyObject(reply);

    reply = (redisReply *)redisCommand(c, "LPOP P2C");

    // Check if reply is valid
    if (reply == NULL) {
      printf("Error: %s\n", c->errstr);
    } else {
      if (reply->type == REDIS_REPLY_STRING) {
        // Get the raw binary data from Redis reply
        uint8_t *retrieved_data = (uint8_t *)reply->str;
        size_t   retrieved_data_len = reply->len;

        // Print out the raw data for debugging (hex format)
        printf("Retrieved binary data (in hex): ");
        for (size_t i = 0; i < retrieved_data_len; i++) {
          printf("%02X ", retrieved_data[i]);
        }
        printf("\n");
      } else if (reply->type != REDIS_REPLY_NIL) {
        // if it is not empty message (no item in the queue)
        printf(
            "LPOP did not return a valid string/binary data. Reply type: %d \n",
            reply->type);
      }
    }
    freeReplyObject(reply);
  }

  u32 havoc_steps = 1 + rand_below(data->afl, 16);

  /* set everything up, costly ... :( */
  memcpy(data->buf, buf, buf_size);

  /* the mutation */
  u32 out_buf_len = afl_mutate(data->afl, data->buf, buf_size, havoc_steps,
                               false, true, add_buf, add_buf_size, max_size);

  /* return size of mutated data */
  *out_buf = data->buf;
  return out_buf_len;
}

/**
 * Deinitialize everything
 *
 * @param data The data ptr from afl_custom_init
 */
void afl_custom_deinit(my_mutator_t *data) {
  free(data->buf);
  free(data);
  if (c) redisFree(c);
}
