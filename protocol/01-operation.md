# Operation

## High Level Operation

This section covers the high-level processes for interacting with DSD, this is supported by lower level operations that enable storage and querying using the DHT.

### Connecting to the network
1. Generate a new keypair and DatabaseID for the new node (this may be persisted as desired)
2. Connect to a "bootstrap" node (address only) that is already a member of the network
3. Generate a new Primary page containing the node information
4. Publish the new primary page to DSD at the Node DatabaseID

### Publishing a Service
1. Generate a new keypair and Database ID for the new service (this should be stored)
2. Generate a new Primary page containing the service information
3. Publish the new primary page to DSD at the Service DatabaseID

### Updating a Service
1. Update the service information / definition
2. Generate an updated Primary page containing the service updated information
3. Publish the updated primary page to DSD at the Service DatabaseID

### Locating a Service
1. Search for pages at a given ID
2. Parse and Reduce returned pages

## Low Level Operation

### Receiving a message
1. Locate the public key associated with the peer (from the database or local cache)
2. Validate the message signature against discovered ID
3. Add public key to local cache
4. Handle message and reply

### Storing a Primary Page
1. Locate the public key associated with the page ID (included in page, from the database, from the local cache)
2. Validate the ID matches the public key
3. Validate the signature
4. Parse the options
5. Check required options exist
6. Store page

### Storing a Secondary Page
1. Find the public key associated with the peer ID (from the database or local cache)

### Receiving a (Requested) Page
1. Find the public key associated with the page ID (included in page, from the database, from the local cache)
2. Validate the message signature against discovered ID
3. Add public key to local cache
4. Return page

### Handling failures
On a signature verification failure
- increment peer failure count
- if failure count > max failures, add ID / Address to block list
