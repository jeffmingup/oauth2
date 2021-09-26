package main

import (
	"context"
	"crypto/md5"
	"encoding/base64"
	"encoding/json"
	goerrors "errors"
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"time"

	"github.com/go-oauth2/oauth2/v4/generates"
	"github.com/go-redis/redis/v8"
	"gorm.io/gorm"

	"github.com/golang-jwt/jwt"

	"github.com/go-oauth2/oauth2/v4/errors"
	"github.com/go-oauth2/oauth2/v4/internal/pkg/db"
	"github.com/go-oauth2/oauth2/v4/internal/pkg/tool"
	"github.com/go-oauth2/oauth2/v4/manage"
	"github.com/go-oauth2/oauth2/v4/models"
	"github.com/go-oauth2/oauth2/v4/server"
	"github.com/go-oauth2/oauth2/v4/store"
	"github.com/go-session/session"
)

var (
	dumpvar   bool
	idvar     string
	secretvar string
	domainvar string
	portvar   int
)

func init() {
	flag.BoolVar(&dumpvar, "d", false, "Dump requests and responses")
	flag.StringVar(&idvar, "i", "222222", "The client id being passed in")
	flag.StringVar(&secretvar, "s", "22222222", "The client secret being passed in")
	flag.StringVar(&domainvar, "r", "http://localhost:9094", "The domain of the redirect url")
	flag.IntVar(&portvar, "p", 9096, "the base port for the server")
}

func main() {
	flag.Parse()
	log.SetFlags(log.LstdFlags | log.Llongfile)
	if dumpvar {
		log.Println("Dumping requests")
	}
	manager := manage.NewDefaultManager()
	manager.SetAuthorizeCodeTokenCfg(manage.DefaultAuthorizeCodeTokenCfg)

	// token store
	manager.MustTokenStorage(store.NewMemoryTokenStore())

	// generate jwt access token
	manager.MapAccessGenerate(generates.NewJWTAccessGenerate("", []byte("00000000"), jwt.SigningMethodHS256))
	// manager.MapAccessGenerate(generates.NewAccessGenerate())

	clientStore := store.NewClientStore()
	// clientStore.Set(idvar, &models.Client{
	// 	ID:     idvar,
	// 	Secret: secretvar,
	// 	Domain: domainvar,
	// })

	//把数据库中的客户端信息存入内存
	type clientDetail struct {
		ID     string `gorm:"column:CLIENT_ID;primaryKeys"`
		Secret string `gorm:"column:CLIENT_SECRET"`
		Domain string `gorm:"column:WEB_SERVER_REDIRECT_URI"`
	}

	var clientDetails []clientDetail
	db.DB.Table("oauth_client_details").Find(&clientDetails)
	log.Println(clientDetails)
	for _, v := range clientDetails {
		log.Println(v.ID)
		clientStore.Set(v.ID, &models.Client{
			ID:     v.ID,
			Secret: v.Secret,
			Domain: v.Domain,
		})
	}

	manager.MapClientStorage(clientStore)

	log.Println(clientStore.GetByID(context.TODO(), "uxin"))
	srv := server.NewServer(server.NewConfig(), manager)

	// srv.SetPasswordAuthorizationHandler(func(username, password string) (userID string, err error) {
	// 	if username == "test" && password == "test" {
	// 		userID = "test"
	// 	}
	// 	return
	// })

	srv.SetPasswordAuthorizationHandler(validatePassword)

	srv.SetUserAuthorizationHandler(userAuthorizeHandler)

	srv.SetInternalErrorHandler(func(err error) (re *errors.Response) {
		log.Println("Internal Error:", err.Error())
		return
	})

	srv.SetResponseErrorHandler(func(re *errors.Response) {
		log.Println("Response Error:", re.Error.Error())
	})

	http.HandleFunc("/login", loginHandler)
	http.HandleFunc("/auth", authHandler)
	http.HandleFunc("/favicon.ico", func(rw http.ResponseWriter, r *http.Request) {
		rw.Write([]byte("777"))
	})
	http.HandleFunc("/oauth/authorize", func(w http.ResponseWriter, r *http.Request) {
		if dumpvar {
			dumpRequest(os.Stdout, "authorize", r)
		}

		store, err := session.Start(r.Context(), w, r)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		var form url.Values
		if v, ok := store.Get("ReturnUri"); ok {
			form = v.(url.Values)
		}
		r.Form = form

		store.Delete("ReturnUri")
		store.Save()

		err = srv.HandleAuthorizeRequest(w, r)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
		}
	})

	http.HandleFunc("/oauth/token", func(w http.ResponseWriter, r *http.Request) {
		if dumpvar {
			_ = dumpRequest(os.Stdout, "token", r) // Ignore the error
		}

		err := srv.HandleTokenRequest(w, r)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
		}
	})

	http.HandleFunc("/test", func(w http.ResponseWriter, r *http.Request) {
		if dumpvar {
			_ = dumpRequest(os.Stdout, "test", r) // Ignore the error
		}
		token, err := srv.ValidationBearerToken(r)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}

		data := map[string]interface{}{
			"expires_in": int64(token.GetAccessCreateAt().Add(token.GetAccessExpiresIn()).Sub(time.Now()).Seconds()),
			"client_id":  token.GetClientID(),
			"user_id":    token.GetUserID(),
		}
		e := json.NewEncoder(w)
		e.SetIndent("", "  ")
		e.Encode(data)
	})

	log.Printf("Server is running at %d port.\n", portvar)
	log.Printf("Point your OAuth client Auth endpoint to %s:%d%s", "http://localhost", portvar, "/oauth/authorize")
	log.Printf("Point your OAuth client Token endpoint to %s:%d%s", "http://localhost", portvar, "/oauth/token")
	log.Fatal(http.ListenAndServe(fmt.Sprintf(":%d", portvar), nil))
}

func dumpRequest(writer io.Writer, header string, r *http.Request) error {
	data, err := httputil.DumpRequest(r, true)
	if err != nil {
		return err
	}
	writer.Write([]byte("\n" + header + ": \n"))
	writer.Write(data)
	return nil
}

func userAuthorizeHandler(w http.ResponseWriter, r *http.Request) (userID string, err error) {
	if dumpvar {
		_ = dumpRequest(os.Stdout, "userAuthorizeHandler", r) // Ignore the error
	}
	store, err := session.Start(r.Context(), w, r)
	if err != nil {
		return
	}

	uid, ok := store.Get("LoggedInUserID")
	if !ok {
		if r.Form == nil {
			r.ParseForm()
		}

		store.Set("ReturnUri", r.Form)
		store.Save()

		w.Header().Set("Location", "/login")
		w.WriteHeader(http.StatusFound)
		return
	}

	userID = uid.(string)
	store.Delete("LoggedInUserID")
	store.Save()
	return
}

func loginHandler(w http.ResponseWriter, r *http.Request) {
	if dumpvar {
		_ = dumpRequest(os.Stdout, "login", r) // Ignore the error
	}
	store, err := session.Start(r.Context(), w, r)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	if r.Method == "POST" {
		if r.Form == nil {
			if err := r.ParseForm(); err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}
		}
		store.Set("LoggedInUserID", r.Form.Get("username"))
		store.Save()

		w.Header().Set("Location", "/auth")
		w.WriteHeader(http.StatusFound)
		return
	}
	outputHTML(w, r, "static/login.html")
}

func authHandler(w http.ResponseWriter, r *http.Request) {
	if dumpvar {
		_ = dumpRequest(os.Stdout, "auth", r) // Ignore the error
	}
	store, err := session.Start(nil, w, r)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	if _, ok := store.Get("LoggedInUserID"); !ok {
		w.Header().Set("Location", "/login")
		w.WriteHeader(http.StatusFound)
		return
	}

	outputHTML(w, r, "static/auth.html")
}

func outputHTML(w http.ResponseWriter, req *http.Request, filename string) {
	file, err := os.Open(filename)
	if err != nil {
		http.Error(w, err.Error(), 500)
		return
	}
	defer file.Close()
	fi, _ := file.Stat()
	http.ServeContent(w, req, file.Name(), fi.ModTime(), file)
}

func validatePassword(username, password string) (userID string, err error) {

	//password 进行aes解密
	passwordByte, err := base64.StdEncoding.DecodeString(password)
	if err != nil {
		return "", err
	}
	key := []byte("ABCDEFGHIJKLMNOP") // 加密的密钥
	password = string(tool.AesDecryptCBC(passwordByte, key))
	// log.Println("解密后的password:", password)

	pwd, err := db.Redis.Get(context.TODO(), username).Result()
	if err != nil && err != redis.Nil {
		return "", err
	}

	if err == redis.Nil {
		type User struct {
			UserName string `gorm:"column:USERNAME;primaryKey"`
			Password string `gorm:"column:PWD"`
		}
		var user User
		err := db.DB.Table("sys_user").First(&user, username).Error
		if err != nil && !goerrors.Is(err, gorm.ErrRecordNotFound) {
			return "", err
		}
		if goerrors.Is(err, gorm.ErrRecordNotFound) {
			return "", nil
		}
		pwd = user.Password
		if err := db.Redis.SetNX(context.TODO(), user.UserName, user.Password, 600*time.Second).Err(); err != nil {
			return "", err
		}
	}

	// if pwd == password {
	// 	// log.Println(username, pwd)
	// 	return username, nil
	// }
	md5Data := md5.Sum([]byte(password))
	md5Data = md5.Sum(md5Data[:])
	// log.Print("password的MD5值：")
	// log.Printf("%x\n", md5Data)
	if pwd != "" {
		// log.Println(username, pwd)
		return username, nil
	}
	return "", goerrors.New("incorrect account password")
}
