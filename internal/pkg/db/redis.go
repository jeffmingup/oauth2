package db

import (
	"context"

	"github.com/go-redis/redis/v8"
	"github.com/spf13/viper"
)

var Redis *redis.Client

func RedisInit() {
	Redis = redis.NewClient(&redis.Options{
		Addr:     viper.GetString("redis.addr"),
		Password: viper.GetString("redis.password"), // no password set
		DB:       viper.GetInt("redis.db"),  // use default DB
	})
	_, err := Redis.Ping(context.TODO()).Result()
	if err != nil {
		panic(err)
	}
}
