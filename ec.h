/*
 * ec.h
 *
 *  Created on: Apr 14, 2010
 *      Author: ahmad
 */

#ifndef EC_H_
#define EC_H_

/**
 * MACROS
 */
#define IPCOMP(addr, n) ((addr >> (24 - 8 * n)) & 0xFF)

/**
 * Global Declarations
 */
#define SIG_TEST 44	// Signal for kernel-user communication - debug purposes

#define EMULATE_WNIC 0 // account for WNIC transition times - sleep to wake and vice versa




#endif /* EC_H_ */
