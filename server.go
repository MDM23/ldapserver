package ldapserver

import (
	"bufio"
	"net"
	"time"
)

// Server is an LDAP server.
type Server struct {
	Listener     net.Listener
	ReadTimeout  time.Duration // optional read timeout
	WriteTimeout time.Duration // optional write timeout
	// wg           sync.WaitGroup // group of goroutines (1 by client)
	chDone  chan bool // Channel Done, value => shutdown
	clients map[int]*client

	// OnNewConnection, if non-nil, is called on new connections.
	// If it returns non-nil, the connection is closed.
	OnNewConnection func(c net.Conn) error

	// Handler handles ldap message received from client
	// it SHOULD "implement" RequestHandler interface
	Handler Handler
}

//NewServer return a LDAP Server
func NewServer() *Server {
	return &Server{
		chDone:  make(chan bool),
		clients: make(map[int]*client),
	}
}

// Handle registers the handler for the server.
// If a handler already exists for pattern, Handle panics
func (s *Server) Handle(h Handler) {
	if s.Handler != nil {
		panic("LDAP: multiple Handler registrations")
	}
	s.Handler = h
}

// Listen uses the given Listener to handle incoming requests.
func (s *Server) Listen(listener *net.Listener, options ...func(*Server)) error {
	s.Listener = *listener
	Logger.Printf("Listening on %s\n", s.Listener.Addr())

	for _, option := range options {
		option(s)
	}

	return s.serve()
}

// ListenAndServe listens on the TCP network address s.Addr and then
// calls Serve to handle requests on incoming connections.  If
// s.Addr is blank, ":389" is used.
func (s *Server) ListenAndServe(addr string, options ...func(*Server)) error {
	if addr == "" {
		addr = ":389"
	}

	listener, e := net.Listen("tcp", addr)
	if e != nil {
		return e
	}

	return s.Listen(&listener)
}

// Handle requests messages on the ln listener
func (s *Server) serve() error {
	defer s.Listener.Close()

	if s.Handler == nil {
		Logger.Panicln("No LDAP Request Handler defined")
	}

	i := 0

	for {
		select {
		case <-s.chDone:
			Logger.Print("Stopping server")
			return nil
		default:
		}

		rw, err := s.Listener.Accept()

		if s.ReadTimeout != 0 {
			rw.SetReadDeadline(time.Now().Add(s.ReadTimeout))
		}
		if s.WriteTimeout != 0 {
			rw.SetWriteDeadline(time.Now().Add(s.WriteTimeout))
		}
		if nil != err {
			if opErr, ok := err.(*net.OpError); ok && opErr.Timeout() {
				continue
			}
			Logger.Println(err)
		}

		cli, err := s.newClient(rw)
		if err != nil {
			continue
		}

		i = i + 1
		cli.Numero = i
		Logger.Printf("Connection client [%d] from %s accepted", cli.Numero, cli.RemoteAddr().String())

		s.clients[i] = cli
		// s.wg.Add(1)

		go cli.serve()

		// go func() {
		// 	cli.serve()
		// 	s.wg.Done()
		// }()
	}
}

// Return a new session with the connection
// client has a writer and reader buffer
func (s *Server) newClient(conn net.Conn) (c *client, err error) {
	c = &client{
		Conn: conn,
		// srv: s,
		// rwc: rwc,
		br:              bufio.NewReader(conn),
		bw:              bufio.NewWriter(conn),
		onNewConnection: s.OnNewConnection,
		Handler:         s.Handler,
		ReadTimeout:     s.ReadTimeout,
		WriteTimeout:    s.WriteTimeout,
	}
	return c, nil
}

// Termination of the LDAP session is initiated by the server sending a
// Notice of Disconnection.  In this case, each
// protocol peer gracefully terminates the LDAP session by ceasing
// exchanges at the LDAP message layer, tearing down any SASL layer,
// tearing down any TLS layer, and closing the transport connection.
// A protocol peer may determine that the continuation of any
// communication would be pernicious, and in this case, it may abruptly
// terminate the session by ceasing communication and closing the
// transport connection.
// In either case, when the LDAP session is terminated.
func (s *Server) Stop() {
	close(s.chDone)
	Logger.Print("gracefully closing client connections...")

	for _, c := range s.clients {
		if c != nil {
			c.close()
		}
	}

	// s.wg.Wait()
	Logger.Print("all clients connection closed")
	s.Listener.Close()
}
