package throttling

import "sync"
import "time"

// The package is based on the "passing the baton" concurrent pattern.
// We use this + mutexes so we can better/easier control the flow.

type Throttler struct {
	perSecond         uint
	availableTickets  uint
	lock              sync.Mutex
	requestLock       sync.Mutex
	requestWaiting    uint
	generatorsLock    sync.Mutex
	generatorsWaiting uint
	generatorsToRun   uint
	tearDown          bool
}

// Returns a new Throttler, which allows the retrival of up to
// perSecond tickets per second.
//
// After a waiting for a ticket the ticket has either to be returned or used
func NewThrottler(perSecond uint) *Throttler {
	throttler := &Throttler{
		perSecond:        perSecond,
		availableTickets: perSecond,
	}
	throttler.requestLock.Lock()
	throttler.generatorsLock.Lock()

	for i := uint(0); i < perSecond; i++ {
		go throttler.startTicketGenerator()
	}

	return throttler
}

func (throttler *Throttler) startTicketGenerator() {
	for {
		if throttler.tearDown {
			return
		}

		throttler.lock.Lock()
		if throttler.generatorsToRun == 0 {
			throttler.generatorsWaiting++
			throttler.lock.Unlock()
			throttler.generatorsLock.Lock()
		}

		throttler.generatorsToRun--
		throttler.availableTickets++

		throttler.passTheBaton()

		time.Sleep(time.Second)
	}
}

// Blocks until a ticket is available. Afterwards either ReturnUnusedTicket() or
// UseTicket has to be called.
func (throttler *Throttler) RequestTicket() {
	throttler.lock.Lock()
	if throttler.availableTickets == 0 {
		throttler.requestWaiting++
		throttler.lock.Unlock()
		throttler.requestLock.Lock()
	}

	throttler.availableTickets--

	throttler.passTheBaton()
}

func (throttler *Throttler) ReturnUnusedTicket() {
	throttler.lock.Lock()

	throttler.availableTickets++

	throttler.passTheBaton()
}

// This function has to be called when actually using a requested ticket,
// otherwise no new ticket will be generated.
func (throttler *Throttler) UseTicket() {
	throttler.lock.Lock()

	throttler.generatorsToRun++

	throttler.passTheBaton()
}

func (throttler *Throttler) passTheBaton() {
	if throttler.generatorsWaiting > 0 && throttler.generatorsToRun > 0 {
		throttler.generatorsWaiting--
		throttler.generatorsLock.Unlock()
	} else if throttler.requestWaiting > 0 && throttler.availableTickets > 0 {
		throttler.requestWaiting--
		throttler.requestLock.Unlock()
	} else {
		throttler.lock.Unlock()
	}
}

// Tears down the throttler. It is the callers responsibility that no thread is
// in RequestTicket(). Whether the threads in RequestTicket() are woken up or not
// is completely undefined.
func (throttler *Throttler) TearDown() {
	throttler.lock.Lock()
	throttler.tearDown = true
	throttler.generatorsToRun = throttler.perSecond
	throttler.passTheBaton()
}
