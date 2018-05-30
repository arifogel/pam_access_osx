% PAM_ACCESS_OSX(8) pam_access_osx PAM module manual

# NAME

pam_acess_osx - PAM module for access-control-list-based authentication.

# SYNOPSIS

**pam_access_osx.so** [debug]

# DESCRIPTION

The **pam_access_osx** module supports the **auth** _function-class_. It is used to provide an access-control-list-based policy for authenticating users. The module supports filtering based on username, group membership,and remote host.

# OPTIONS

debug
:   Output debug messages to syslog

# RETURN VALUES

PAM_SUCCESS
:   The user was successfully authenticated by the access policy.

PAM_AUTH_ERR
:   An error occurred determining whether the user should be authenticated.

PAM_PERM_DENIED
:   The user was denied authentication by the access policy.

# FILES

/etc/security/access.conf
:   Configuration file containing access-control policy to be used by **pam_access_osx**.

# SEE ALSO
**access.conf**(5).
