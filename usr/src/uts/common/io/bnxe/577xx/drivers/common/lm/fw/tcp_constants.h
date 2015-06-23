#ifndef __TCP_CONSTANTS_H_
#define __TCP_CONSTANTS_H_

/**
* This file defines HSI constants for the TCP flows
*/

#define T_TCP_ISLE_ARRAY_SIZE					256
#define T_TCP_MAX_ISLES_PER_CONNECTION_TOE		16    // minimum 1 isle per connection, maximum 254 (because isle numbers 0 and 255 are reserved)
#define T_TCP_MAX_ISLES_PER_CONNECTION_ISCSI	32    // minimum 1 isle per connection, maximum 254 (because isle numbers 0 and 255 are reserved)

#endif /*__TCP_CONSTANTS_H_ */
