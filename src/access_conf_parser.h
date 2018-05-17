#ifndef __ACCESS_CONF_PARSER_H__
#define __ACCESS_CONF_PARSER_H__

/**
 * Validate the format of the access.conf file located at supplied path.
 * Returns 0 if successful, non-zero value otherwise.
 */
int
validate(
    const char* path
);

#endif /* __ACCESS_CONF_PARSER_H__ */

