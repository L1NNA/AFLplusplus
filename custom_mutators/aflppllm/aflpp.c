#include "afl-fuzz.h"
#include <string.h>
#include "afl-mutations.h"
#include <hiredis/hiredis.h>

// windows host
//#define REDIS_HOST "host.docker.internal"

// linux host
// #define REDIS_HOST "172.17.0.1"

// host
#define REDIS_HOST "130.15.5.140" // change to your host IP

#define REDIS_PORT 6379
#define REDIS_PASSWORD "password"
#define CONSUMER_NAME "ToFuzzer"
#define PRODUCER_NAME "ToModel"
#define SET_NAME "message_set"
#define MAX_QUEUE_SIZE 30

redisContext *c;

// Lua script for adding unique messages
const char *lua_script =
    // "if redis.call('SISMEMBER', KEYS[1], ARGV[1]) == 0 then "
    "if 0 == 0 then "
    "   redis.call('SADD', KEYS[1], ARGV[1]) "
    "   redis.call('RPUSH', KEYS[2], ARGV[1]) "
    "   redis.call('LTRIM', KEYS[2], -ARGV[2], -1) "
    "   return 1 "
    "else "
    "   return 0 "
    "end";

char *convert_unit8_as_string(uint8_t *buf, size_t buf_length) {
    // Allocate a char buffer (length + 1 for null terminator)
    char *char_message = (char *)malloc(buf_length + 1);
    if (!char_message) {
        fprintf(stderr, "Memory allocation failed\n");
        return NULL;
    }

    // Copy the data from uint8_t to char
    memcpy(char_message, buf, buf_length);
    char_message[buf_length] = '\0'; // Null-terminate the string

    // Print the string
    printf("Converted message: %s\n", char_message);

    return char_message;
}

void publish_message(redisContext *c, const char *message) {
  redisReply *reply;

  reply = redisCommand(c, "EVAL %s 2 %s %s %s %d", lua_script, SET_NAME,
                       PRODUCER_NAME, message, MAX_QUEUE_SIZE);
  if (reply == NULL) {
    printf("Error: %s\n", c->errstr);
    return;
  }

  if (reply->integer == 1) {
    printf("Published: %s\n", message);
  } else {
    printf("Message %s is a duplicate and was not added.\n", message);
  }

  freeReplyObject(reply);
}

void consume_messages(redisContext *c) {
  redisReply *reply;

  while (1) {
    reply = redisCommand(c, "LLEN %s", CONSUMER_NAME);
    if (reply == NULL) {
      printf("Error: %s\n", c->errstr);
      return;
    }

    if (reply->integer == 0) {
      printf("No messages in the queue. Terminating consumer...\n");
      freeReplyObject(reply);
      break;
    }

    freeReplyObject(reply);

    reply = redisCommand(c, "LPOP %s", CONSUMER_NAME);
    if (reply == NULL) {
      printf("Error: %s\n", c->errstr);
      return;
    }

    if (reply->type == REDIS_REPLY_STRING) {
      printf("Consumed: %s\n", reply->str);
      // Simulate message processing
      // sleep(2);

      // Remove the message from the set
      redisReply *set_reply =
          redisCommand(c, "SREM %s %s", SET_NAME, reply->str);
      if (set_reply == NULL) {
        printf("Error: %s\n", c->errstr);
        freeReplyObject(reply);
        return;
      }

      freeReplyObject(set_reply);

      // Trim the list
      redisReply *trim_reply =
          redisCommand(c, "LTRIM %s -%d -1", CONSUMER_NAME, MAX_QUEUE_SIZE);
      if (trim_reply == NULL) {
        printf("Command failed\n");
        redisFree(c);
        exit(1);
      }
      freeReplyObject(trim_reply);

    } else {
      printf("No messages to consume. Waiting...\n");
    }

    freeReplyObject(reply);
    // sleep(1);  // Simulate a delay before the next iteration
  }
}

typedef struct my_mutator {
  afl_state_t *afl;
  u8          *buf;
  u32          buf_size;

} my_mutator_t;

my_mutator_t *afl_custom_init(afl_state_t *afl, unsigned int seed) {
  redisReply *reply;
  c = redisConnect(REDIS_HOST, REDIS_PORT);
  if (c == NULL || c->err) {
    if (c) {
      printf("Connection error: %s\n", c->errstr);
      redisFree(c);
    } else {
      printf("Connection error: can't allocate redis context\n");
    }
  } else {
    reply = redisCommand(c, "AUTH %s", REDIS_PASSWORD);
    if (reply == NULL) {
      printf("Error: %s\n", c->errstr);
      redisFree(c);
    }
    printf("Connected!");
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

  //if (c) consume_message(c);
  // if (consumed_size > 0){
  //   buf = append_to_buf(buf, buf_size, consumed_messages, consumed_size);
  // }
  //if (c) publish_message(c, "hello!!!");
  // send buffer
  //printf("buff: %s\nbuf_size: %d\n", buf, buf_size);
  char *message=convert_unit8_as_string(buf, buf_size);
  printf("buff: %s\nbuf_size: %d\nadd_buf: %s\nadd_buf_size: %d\n", buf, buf_size, add_buf, add_buf_size);
  if (c) publish_message(c, message);
  // Clean up
  free(message);

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
