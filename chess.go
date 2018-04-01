package main

import (
	"database/sql"
	"fmt"
	"html/template"
	"net/http"
	"os"
	"regexp"
	"strconv"
	"strings"

	"golang.org/x/crypto/bcrypt"
	mailgun "gopkg.in/mailgun/mailgun-go.v1"

	"github.com/gin-contrib/static"
	"github.com/gin-gonic/gin"
	_ "github.com/lib/pq"
	uuid "github.com/satori/go.uuid"
)

const (
	dbhost = "DBHOST"
	dbport = "DBPORT"
	dbuser = "DBUSER"
	dbpass = "DBPASS"
	dbname = "DBNAME"
)

type challenge struct {
	Acceptor, Date, ID, Initiator, Winner, WinningString string
	Opponent                                             struct {
		Fname, Lname string
	}
}

type confirmData struct {
	Error       string
	Achallenges []challenge
	Ichallenges []challenge
}

type session struct {
	pid int16
	uid string
}

type user struct {
	Email, Fname, Lname, Password, UUID string
	ID, Score                           int16
}

type userAuth struct {
	Email, Fname, Lname, Password string
	ID, Score                     int16
}

type users struct {
	Users []user
}

var tpl *template.Template
var db *sql.DB

func main() {
	url := "http://localhost"
	r := gin.Default()
	tpl = template.Must(template.New("").ParseGlob("data/templates/*.gohtml"))
	private, _ := os.LookupEnv("PRIVATE")
	public, _ := os.LookupEnv("PUBLIC")
	mg := mailgun.NewMailgun("mail.therileyjohnson.com", private, public)
	initDb()

	/* HELPER FUNCTIONS */
	checkAuth := func(c *gin.Context, f func(*gin.Context)) {
		if isActiveSession(c.Request) {
			f(c)
		} else {
			players := users{}
			queryPlayers(&players)
			tpl.ExecuteTemplate(c.Writer, "indexOut.gohtml", players)
		}
	}

	/* FILE HANDLERS */
	r.GET("/static/css/:fi", static.Serve("/static/css", static.LocalFile("static/css/", true)))
	r.GET("/static/img/:fi", static.Serve("/static/img", static.LocalFile("static/img/", true)))
	r.GET("/static/js/:fi", static.Serve("/static/js", static.LocalFile("static/js/", true)))
	r.GET("/static/custom/:fi", static.Serve("/static/custom", static.LocalFile("static/custom/", true)))
	r.GET("/favicon.ico", func(g *gin.Context) { http.ServeFile(g.Writer, g.Request, "/static/img/favicon.ico") })

	/* ROUTE HANDLERS */
	r.GET("/", func(g *gin.Context) {
		players := users{}
		queryPlayers(&players)
		if isActiveSession(g.Request) {
			tpl.ExecuteTemplate(g.Writer, "indexIn.gohtml", players)
		} else {
			tpl.ExecuteTemplate(g.Writer, "indexOut.gohtml", players)
		}
	})

	r.POST("/accept/:id", func(c *gin.Context) {
		checkAuth(c, func(g *gin.Context) {
			var ascore, iscore int
			id := g.Param("id")
			uid, _ := g.Request.Cookie("uuid")
			c := challenge{}

			db.QueryRow(`SELECT date, acceptor, initiator, id, winner FROM PLAYER_CHALLENGES
				ORDER WHERE acceptor=$1 AND id=$2`, uid.Value, id).Scan(&c.Date, &c.Acceptor, &c.Initiator, &c.ID, &c.Winner)
			db.QueryRow(`SELECT score FROM PLAYERS
					ORDER WHERE uuid=$2`, c.Initiator).Scan(&iscore)
			db.QueryRow(`SELECT score FROM PLAYERS
				ORDER WHERE uuid=$2`, c.Initiator).Scan(&iscore)

			if c.Winner == c.Initiator {
				db.Query("UPDATE films SET score=$1 WHERE uuid=$2", ascore-1, c.Acceptor)
				db.Query("UPDATE films SET score=$1 WHERE uuid=$2", iscore+1, c.Initiator)
			} else {
				db.Query("UPDATE films SET score=$1 WHERE uuid=$2", ascore+1, c.Acceptor)
				db.Query("UPDATE films SET score=$1 WHERE uuid=$2", iscore-1, c.Initiator)
			}

			db.Query("DELETE FROM PLAYER_CHALLENGES WHERE acceptor=$1 AND id=$2", uid.Value, id)

			cd := confirmData{}
			getAcceptData(g.Request, &cd)
			getInitiatData(g.Request, &cd)
			tpl.ExecuteTemplate(g.Writer, "gameConfirm.gohtml", cd)
		})
	})

	r.POST("/cancel/:id", func(c *gin.Context) {
		checkAuth(c, func(g *gin.Context) {
			id := g.Param("id")
			uid := getIDFromSession(g.Request)
			db.Query("DELETE FROM PLAYER_CHALLENGES WHERE initiator=$1 AND id=$2", uid, id)
			g.Redirect(303, "/confirm")
		})
	})

	r.GET("/confirm", func(c *gin.Context) {
		checkAuth(c, func(g *gin.Context) {
			renderGameConfirmation(g)
		})
	})

	r.POST("/confirm", func(c *gin.Context) {
		checkAuth(c, func(g *gin.Context) {
			err := addChallenge(g)
			if err != nil {
				tpl.ExecuteTemplate(g.Writer, "error.gohtml", err.Error())
			} else {
				g.Redirect(303, "/confirm")
			}
		})
	})

	r.POST("/deny/:id", func(c *gin.Context) {
		checkAuth(c, func(g *gin.Context) {
			id := g.Param("id")
			uid := getIDFromSession(g.Request)
			db.Query("DELETE FROM PLAYER_CHALLENGES WHERE acceptor=$1 AND id=$2", uid, id)
			g.Redirect(303, "/confirm")
		})
	})

	r.GET("/login", func(g *gin.Context) {
		if isActiveSession(g.Request) {
			tpl.ExecuteTemplate(g.Writer, "error.gohtml", "You're already logged in!")
		} else {
			tpl.ExecuteTemplate(g.Writer, "login.gohtml", nil)
		}
	})

	r.POST("/login", func(g *gin.Context) {
		email := strings.ToLower(g.PostForm("email"))
		password := g.PostForm("password")
		ua := userAuth{}
		err := db.QueryRow("SELECT * FROM PLAYERS WHERE email=$1", email).Scan(&ua.Email, &ua.Fname, &ua.Lname, &ua.Password, &ua.Score, &ua.ID)
		if err == sql.ErrNoRows {
			tpl.ExecuteTemplate(g.Writer, "login.gohtml", "BAD LOGIN!")
		} else {
			if checkPasswordHash(password, ua.Password) {
				uid := getUUID()
				http.SetCookie(g.Writer, &http.Cookie{Name: "uuid", Value: uid})
				db.Query("INSERT INTO PLAYER_SESSIONS (pid, uuid) VALUES ($1, $2)", ua.ID, uid)
				players := users{}
				queryPlayers(&players)
				tpl.ExecuteTemplate(g.Writer, "indexIn.gohtml", players)
			} else {
				tpl.ExecuteTemplate(g.Writer, "login.gohtml", "BAD LOGIN!")
			}
		}
	})

	r.GET("/logout", func(g *gin.Context) {
		if isActiveSession(g.Request) {
			val, _ := g.Request.Cookie("uuid")
			http.SetCookie(g.Writer, &http.Cookie{Name: "uuid", MaxAge: -1})
			_, err := db.Query("DELETE FROM PLAYER_SESSIONS WHERE uuid=$1", val.Value)
			if err != nil {
				fmt.Println(err)
			}
			g.Redirect(307, "/")
		} else {
			tpl.ExecuteTemplate(g.Writer, "login.gohtml", nil)
		}
	})

	r.GET("/profile", func(c *gin.Context) {
		checkAuth(c, func(g *gin.Context) {
			id := getIDFromSession(g.Request)
			player, err := queryPlayer(id)

			if err != nil {
				tpl.ExecuteTemplate(g.Writer, "error.gohtml", "Error fetching your profile, sorry")
			}

			tpl.ExecuteTemplate(g.Writer, "myProfile.gohtml", player)
		})
	})

	r.GET("/profile/:id", func(g *gin.Context) {
		id, err := strconv.ParseUint(g.Param("id"), 10, 32)
		if err == nil {
			player, err := queryPlayer(id)
			if err == sql.ErrNoRows {
				tpl.ExecuteTemplate(g.Writer, "error.gohtml", "That player ID does not exist")
			} else if err != nil {
				tpl.ExecuteTemplate(g.Writer, "error.gohtml", "Error finding player with that ID")
			} else if isActiveSession(g.Request) {
				tpl.ExecuteTemplate(g.Writer, "profileIn.gohtml", player)
			} else {
				tpl.ExecuteTemplate(g.Writer, "profileOut.gohtml", player)
			}
		} else {
			tpl.ExecuteTemplate(g.Writer, "error.gohtml", "That's not a valid player ID")
		}
	})

	r.GET("/register", func(g *gin.Context) {
		tpl.ExecuteTemplate(g.Writer, "register.gohtml", nil)
	})

	r.POST("/register", func(g *gin.Context) {
		matchEmail := false
		emailDomains := []string{"trojans.dsu.edu", "pluto.dsu.edu", "dsu.edu"}
		email := strings.ToLower(g.PostForm("email"))
		for _, emailRegex := range emailDomains {
			r := regexp.MustCompile(fmt.Sprintf(`^[A-Za-z0-9][A-Za-z0-9_\+\.]*@%s$`, emailRegex))
			if r.Match([]byte(email)) {
				matchEmail = true
			}
		}
		if !matchEmail {
			tpl.ExecuteTemplate(g.Writer, "register.gohtml", "EMAIL FORMAT IS INVALID!")
			return
		}
		fname := g.PostForm("fname")
		lname := g.PostForm("lname")
		password := g.PostForm("password")
		cpassword := g.PostForm("cpassword")
		if cpassword != password {
			tpl.ExecuteTemplate(g.Writer, "register.gohtml", "PASSWORDS DO NOT MATCH!")
			return
		}
		ua := userAuth{}
		err := db.QueryRow("SELECT * FROM PLAYERS WHERE email=$1", email).Scan(&ua.Email)
		fmt.Println(err)
		if err == sql.ErrNoRows {
			var hpassword string
			for hpassword, err = hashPassword(password); err != nil; {
				hpassword, err = hashPassword(password)
			}
			uid := getUUID()
			db.Query("INSERT INTO PLAYER_CONFIRMATION (uuid, email, fname, lname, password) VALUES ($1, $2, $3, $4, $5)", uid, email, fname, lname, hpassword)
			_, _, err = mg.Send(mailgun.NewMessage("robot@mail.therileyjohnson.com", "Registration", fmt.Sprintf("Click %s:4800/register/%s to confirm your email!", url, uid), email))
			if err != nil {
				fmt.Println(err)
			}
			tpl.ExecuteTemplate(g.Writer, "registerFinish.gohtml", nil)
		} else {
			tpl.ExecuteTemplate(g.Writer, "register.gohtml", "USER ALREADY EXISTS!")
		}
	})

	r.GET("/register/:id", func(g *gin.Context) {
		uc := user{}
		err := db.QueryRow("SELECT email, fname, lname, password FROM PLAYER_CONFIRMATION WHERE uuid=$1", g.Param("id")).Scan(&uc.Email, &uc.Fname, &uc.Lname, &uc.Password)
		if err == sql.ErrNoRows {
			tpl.ExecuteTemplate(g.Writer, "registrationBad.gohtml", nil)
			return
		}
		addPlayer(uc.Email, uc.Fname, uc.Lname, uc.Password)
		db.Query("DELETE FROM PLAYER_CONFIRMATION WHERE email=$1", uc.Email)
		uid := getUUID()
		http.SetCookie(g.Writer, &http.Cookie{Name: "uuid", Value: uid})
		db.Query("INSERT INTO PLAYER_CONFIRMATION (pid, uuid) VALUES ($1, $2)", uc.ID, uid)
		tpl.ExecuteTemplate(g.Writer, "registration.gohtml", nil)
	})

	r.Run(":4800")
}

func initDb() {
	config := dbConfig()
	var err error
	psqlInfo := fmt.Sprintf("host=%s port=%s user=%s password=%s dbname=%s sslmode=disable",
		config[dbhost], config[dbport], config[dbuser], config[dbpass], config[dbname])

	db, err = sql.Open("postgres", psqlInfo)
	if err != nil {
		panic(err)
	}
	err = db.Ping()
	if err != nil {
		panic(err)
	}
	fmt.Println(fmt.Sprintf("Successfully connected to the %s database!", config[dbname]))
}

func dbConfig() map[string]string {
	conf := make(map[string]string)
	conflist := []string{dbhost, dbport, dbuser, dbpass, dbname}
	for _, config := range conflist {
		con, ok := os.LookupEnv(config)
		if !ok {
			panic(fmt.Sprintf("%s environment variable required but not set", config))
		}
		conf[config] = con
	}
	return conf
}

func addChallenge(c *gin.Context) error {
	pid := getIDFromSession(c.Request)
	oid, err := strconv.ParseUint(c.PostForm("pid"), 10, 32)
	if err != nil {
		return fmt.Errorf("Couldn't parse Opponent ID")
	}

	if pid == oid {
		return fmt.Errorf("Challenger ID cannot be the same as the Acceptor ID")
	}

	wid, err := strconv.ParseUint(c.PostForm("wpid"), 10, 32)

	if err != nil {
		return fmt.Errorf("Couldn't parse Winner ID")
	}

	if wid != oid && wid != pid {
		return fmt.Errorf("The Winner ID needs to either be the Challenger ID or Opponent ID")
	}

	date := c.PostForm("date")

	_, err = queryPlayer(oid)

	if err == sql.ErrNoRows {
		return fmt.Errorf("An Opponent with that ID does not exist")
	}

	_, err = db.Query("INSERT INTO PLAYER_challenges values ($1, $2, $3, $4, $5)", getUUID(), date, oid, pid, wid)

	if err != nil {
		return fmt.Errorf("Error with adding the challenge, please try again")
	}

	return nil
}

func getAcceptData(r *http.Request, cd *confirmData) error {
	pid := getIDFromSession(r)
	rows, err := db.Query(`
		SELECT
		date, acceptor, initiator, id, winner
		FROM PLAYER_CHALLENGES
		WHERE acceptor=$1`, pid)

	if err != nil {
		return err
	}

	defer rows.Close()

	for rows.Next() {
		c := challenge{}
		err = rows.Scan(
			&c.Date,
			&c.Acceptor,
			&c.Initiator,
			&c.ID,
			&c.Winner,
		)
		if err != nil {
			return err
		}
		cd.Achallenges = append(cd.Achallenges, c)
	}
	return nil
}

func getInitiatData(r *http.Request, cd *confirmData) error {
	pid := getIDFromSession(r)
	rows, err := db.Query(`
		SELECT
		date, acceptor, initiator, id, winner
		FROM PLAYER_CHALLENGES
		WHERE initiator=$1`, pid)

	if err != nil {
		return err
	}

	defer rows.Close()

	for rows.Next() {
		c := challenge{}
		err = rows.Scan(
			&c.Date,
			&c.Acceptor,
			&c.Initiator,
			&c.ID,
			&c.Winner,
		)
		if err != nil {
			return err
		}
		cd.Ichallenges = append(cd.Ichallenges, c)
	}
	return nil
}

func isActiveSession(r *http.Request) bool {
	val, err := r.Cookie("uuid")
	var id int
	return err == nil && db.QueryRow("SELECT pid FROM PLAYER_SESSIONS WHERE uuid=$1", val.Value).Scan(&id) != sql.ErrNoRows
}

func getIDFromSession(r *http.Request) uint64 {
	var id uint64
	val, _ := r.Cookie("uuid")
	db.QueryRow("SELECT pid FROM PLAYER_SESSIONS WHERE uuid=$1", val.Value).Scan(&id)
	return id
}

func getUUID() string {
	var err error
	var uid uuid.UUID
	for uid, err = uuid.NewV4(); err != nil; {
		uid, err = uuid.NewV4()
	}
	return uid.String()
}

func queryPlayers(U *users) error {
	//Order by descending because the
	//ordering is reversed when
	//appended to the U.Users list
	rows, err := db.Query(`
		SELECT
			email,
			fname,
			lname,
			pid,
			score
		FROM PLAYERS
		ORDER BY score DESC`)

	if err != nil {
		return err
	}

	defer rows.Close()

	for rows.Next() {
		u := user{}
		err = rows.Scan(
			&u.Email,
			&u.Fname,
			&u.Lname,
			&u.ID,
			&u.Score,
		)
		if err != nil {
			return err
		}
		U.Users = append(U.Users, u)
	}

	err = rows.Err()

	if err != nil {
		return err
	}

	return nil
}

func renderGameConfirmation(g *gin.Context) {
	type info struct{ Fname, Lname string }
	pmap := make(map[string]info)
	cd := confirmData{}

	pid := getIDFromSession(g.Request)

	rows, err := db.Query(`SELECT * FROM PLAYER_CHALLENGES WHERE acceptor=$1`, pid)

	if err == nil {
		for rows.Next() && cd.Error == "" {
			c := challenge{}
			err = rows.Scan(
				&c.ID,
				&c.Date,
				&c.Acceptor,
				&c.Initiator,
				&c.Winner,
			)
			if err != nil {
				cd.Error = "Error in getting acceptor data"
			} else {
				if _, exists := pmap[c.Initiator]; !exists {
					oid, _ := strconv.ParseUint(c.Initiator, 10, 32)
					u, _ := queryPlayer(oid)
					pmap[c.Initiator] = info{u.Fname, u.Lname}
				}
				c.Opponent.Fname, c.Opponent.Lname = pmap[c.Initiator].Fname, pmap[c.Initiator].Lname
				if c.Initiator == c.Winner {
					c.WinningString = "won on"
				} else {
					c.WinningString = "lost on"
				}
				cd.Achallenges = append(cd.Achallenges, c)
			}
		}
		rows.Close()

		if err == nil {
			rows, err = db.Query(`SELECT * FROM PLAYER_CHALLENGES WHERE initiator=$1`, pid)
			if err == nil {
				for rows.Next() && cd.Error == "" {
					c := challenge{}
					err = rows.Scan(
						&c.ID,
						&c.Date,
						&c.Acceptor,
						&c.Initiator,
						&c.Winner,
					)
					if err != nil {
						cd.Error = "Error in getting acceptor data"
					} else {
						if _, exists := pmap[c.Acceptor]; !exists {
							oid, _ := strconv.ParseUint(c.Acceptor, 10, 32)
							u, _ := queryPlayer(oid)
							pmap[c.Acceptor] = info{u.Fname, u.Lname}
						}
						c.Opponent.Fname, c.Opponent.Lname = pmap[c.Acceptor].Fname, pmap[c.Acceptor].Lname
						if c.Acceptor == c.Winner {
							c.WinningString = "won on"
						} else {
							c.WinningString = "lost on"
						}
						cd.Ichallenges = append(cd.Ichallenges, c)
					}
				}
				rows.Close()
			}
		}
	} else {
		cd.Error = "Could not get acceptor data"
	}

	tpl.ExecuteTemplate(g.Writer, "gameConfirm.gohtml", cd)
}

func queryPlayer(id uint64) (user, error) {
	row, err := db.Query(`
		SELECT 
		email, fname, lname, pid, score 
		FROM PLAYERS WHERE pid=$1`, id)

	if err != nil {
		return user{}, err
	}

	if err == sql.ErrNoRows {
		return user{}, sql.ErrNoRows
	}

	defer row.Close()

	u := user{}
	row.Next()
	err = row.Scan(
		&u.Email,
		&u.Fname,
		&u.Lname,
		&u.ID,
		&u.Score,
	)

	if err != nil {
		return user{}, err
	}

	return u, nil
}

func addPlayer(e, f, l, p string) error {
	_, err := db.Exec(`INSERT INTO PLAYERS (email, fname, lname, password, score) 
	VALUES ($1, $2, $3, $4, 300)`, e, f, l, p)

	if err != nil {
		return err
	}

	return nil
}

func hashPassword(password string) (string, error) {
	bytes, err := bcrypt.GenerateFromPassword([]byte(password), 14)
	return string(bytes), err
}

func checkPasswordHash(password, hash string) bool {
	err := bcrypt.CompareHashAndPassword([]byte(hash), []byte(password))
	return err == nil
}
