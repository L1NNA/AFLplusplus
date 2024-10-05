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
// const char *lua_script =
//     // "if redis.call('SISMEMBER', KEYS[1], ARGV[1]) == 0 then "
//     "if 0 == 0 then "
//     "   redis.call('SADD', KEYS[1], ARGV[1]) "
//     "   redis.call('RPUSH', KEYS[2], ARGV[1]) "
//     "   redis.call('LTRIM', KEYS[2], -ARGV[2], -1) "
//     "   return 1 "
//     "else "
//     "   return 0 "
//     "end";

void cleanup_message(redisContext *c, uint8_t *message, size_t message_size) {
    redisReply *reply;

    // Remove the message from the set
    reply = redisCommand(c, "SREM %s %b", SET_NAME, message, message_size);
    if (reply == NULL) {
        printf("Error removing from set: %s\n", c->errstr);
        return;
    }
    printf("Removed from set: %.*s\n", (int)message_size, message);
    freeReplyObject(reply);

    // Remove the message from the list
    reply = redisCommand(c, "LREM %s 0 %b", PRODUCER_NAME, message, message_size);
    if (reply == NULL) {
        printf("Error removing from list: %s\n", c->errstr);
        return;
    }
    printf("Removed from list: %.*s\n", (int)message_size, message);
    freeReplyObject(reply);
}

void publish_message(redisContext *c, uint8_t *message, size_t message_size) {
    redisReply *reply;

    // Check if the message is already a member of the set
    reply = redisCommand(c, "SISMEMBER %s %b", SET_NAME, message, message_size);
    if (reply == NULL) {
        printf("Error: %s\n", c->errstr);
        freeReplyObject(reply);
        return;
    }

    if (reply->integer != 0) {
        freeReplyObject(reply);

        // Add to the set
        reply = redisCommand(c, "SADD %s %b", SET_NAME, message, message_size);
        if (reply == NULL){
            printf("Set adding error: %s\n", c->errstr);
            freeReplyObject(reply);
            return;
        }
        freeReplyObject(reply);

        // Push to the list
        reply = redisCommand(c, "RPUSH %s %b", PRODUCER_NAME, message, message_size);
        printf("Published: %s\n", message);
        if(reply == NULL){
            printf("publish message error: %s\n", c->errstr);
            freeReplyObject(reply);
            cleanup_message(c, message, message_size);
            return;
        }
        
        freeReplyObject(reply);

        // Trim the list if it exceeds the maximum length
        reply = redisCommand(c, "LTRIM %s -%d -1", PRODUCER_NAME, MAX_QUEUE_SIZE);
        if (reply == NULL){
            printf("Trim error: %s\n", c->errstr);
            freeReplyObject(reply);
            cleanup_message(c, message, message_size);
            return;
        }
    } else {
        printf("Message %s is a duplicate and was not added.\n", message);
    }
    freeReplyObject(reply);
}

char* consume_messages(redisContext *c) {
  redisReply *reply;
  char *message;
  
  reply = redisCommand(c, "LLEN %s", CONSUMER_NAME);
  if (reply == NULL) {
    printf("Error: %s\n", c->errstr);
    return NULL;
  }

  if (reply->integer == 0) {
    printf("No messages in the queue. Skip...\n");
    freeReplyObject(reply);
    return NULL;
  }

  freeReplyObject(reply);

  reply = redisCommand(c, "LPOP %s", CONSUMER_NAME);
  if (reply == NULL) {
    printf("Error: %s\n", c->errstr);
    return NULL;
  }

  if (reply->type == REDIS_REPLY_STRING) {
    printf("Consumed: %s\n", reply->str);
    message = reply->str;

    // Remove the message from the set
    redisReply *set_reply =
        redisCommand(c, "SREM %s %s", SET_NAME, reply->str);
    if (set_reply == NULL) {
      printf("Error: %s\n", c->errstr);
      freeReplyObject(reply);
      return NULL;
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
    message = NULL;
  }

  freeReplyObject(reply);
  return message;
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

  // publish message
  if (c) publish_message(c, buf, buf_size);

  u32 havoc_steps = 1 + rand_below(data->afl, 16);

  //consume message
  // uint8_t *new_buf = NULL;
  // size_t new_buf_size = 0;
  // if (c) {
  //   char *message = consume_message(c);
  //   if (message){
  //     // the mutation
  //     my_u8_t new_buf_message = convert_char_to_uint8(message);
  //     new_buf = new_buf_message.buf;
  //     new_buf_size = new_buf_message.buf_size;
  //     free(message);
  //     free(new_buf_message.buf);
  //     free(new_buf_message);

  //     memcpy(data->buf, new_buf, new_buf_size);

  //     return new_buf_size;
  //   }
  // }

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
