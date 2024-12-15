package cli

import (
	"bufio"
	"fmt"
	"os"

	"golang.org/x/term"
)

type InterruptError struct{}

func (i InterruptError) Error() string {
	return "Program cancelled."
}

func ChooseInterval() (string, error) {
	options := []string{
		"Every minute - INTENSE logging",
		"Every 15 minutes",
		"Every 30 minutes",
		"Every hour",
	}

	oldState, err := term.MakeRaw(int(os.Stdin.Fd()))
	if err != nil {
		return "", err
	}
	defer term.Restore(int(os.Stdin.Fd()), oldState)

	selected := 0
	for {
		fmt.Print("\033[H\033[2J\033[0;0H")

		writer := bufio.NewWriter(os.Stdout)
		writer.WriteString("Please choose how often to capture open network connections:\n\r")

		for i, opt := range options {
			if i == selected {
				writer.WriteString(fmt.Sprintf("→ %s\n\r", opt))
			} else {
				writer.WriteString(fmt.Sprintf("  %s\n\r", opt))
			}
		}
		writer.Flush()

		b := make([]byte, 1)
		os.Stdin.Read(b)

		switch b[0] {
		case 65: // Up arrow
			if selected > 0 {
				selected--
			}
		case 66: // Down arrow
			if selected < len(options)-1 {
				selected++
			}
		case 13: // Enter
			return options[selected], nil
		case 3: // Ctrl-C
			return "", InterruptError{}
		}
	}
}
