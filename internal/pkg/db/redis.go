package db

import (
	"context"

	"github.com/go-redis/redis/v8"
)

var Redis *redis.Client

func init() {
	Redis = redis.NewClient(&redis.Options{
		Addr:     "localhost:6379",
		Password: "", // no password set
		DB:       0,  // use default DB
	})
	_, err := Redis.Ping(context.TODO()).Result()
	if err != nil {
		panic(err)
	}
}
