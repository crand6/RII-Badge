// CONFIG
#pragma config OSC = RC         // Oscillator selection bits (RC oscillator)
#pragma config WDT = OFF         // Watchdog timer enable bit (WDT enabled)
#pragma config CP = OFF         // Code protection bit (Code protection off)

// #pragma config statements should precede project file includes.
// Use project enums instead of #define for ON and OFF.

#include <xc.h>

// Macros to make it easier to identify LED lights
// PORT A
#define A_BOTTOM_RIGHT (0x1 << 0)
#define A_LOWER_RIGHT (0x1 << 1)
#define A_RIGHT (0x1 << 2)
#define A_UPPER_RIGHT (0x1 << 3)

// PORT B
#define B_TOP_RIGHT (0x1 << 0)
#define B_TOP_LEFT (0x1 << 1)
#define B_UPPER_LEFT (0x1 << 2)
#define B_LEFT (0x1 << 3)
#define B_LOWER_LEFT (0x1 << 4)
#define B_BOTTOM_LEFT (0x1 << 5)


// Flash Delays
#define FAST_FLASH 1600
#define SLOW_FLASH 4000

unsigned short i = 0;
unsigned short delay_i = 0;


void init(void) {
    // Set all PORTA pins as output 
    TRISA = 0x0;
    
    // Set all PORTB pins as output
    TRISB = 0x00;
    
    return;
}

void delay(unsigned int ticks) {
    for (delay_i=0; delay_i < ticks; delay_i++);
    return;
}

void flash(unsigned int count, unsigned int ticks) {
    for (i=0; i < count; i++) {
        PORTA = 0xf;
        PORTB = 0xff;
        delay(ticks);
        PORTA = 0x0;
        PORTB = 0x0;
        delay(ticks);
    }

}

void main(void) {
    init();
    
    while (1) {
        // First flash group
        flash(5, SHORT_FLASH);
        delay(FAST_FLASH);
        
        // Second flash group
        flash(3, SLOW_FLASH);
        
        // Last flash group
        flash(5, FAST_FLASH);
        delay(SLOW_FLASH * 2);
    }
    
    // Should never reach
    return;
}
#endif
