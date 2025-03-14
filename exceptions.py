class AdminPasswordError(Exception):
    """
    Represents an error encountered when managing or validating
    an administrator password.

    This exception is typically raised during operations where
    the administrator password fails validation checks or is
    incorrectly managed in configurations.

    :ivar message: Explanation of the specific admin password error.
    :type message: str
    """

class AdminNotFoundError(Exception):
    """
    Represents an exception that is raised when the requested admin is not found.

    This exception is intended to be used in scenarios where operations require
    the presence of a specific admin user, but the provided identifier does
    not match any existing admin. It facilitates handling such errors uniquely.

    :ivar message: The error message providing details about the missing admin.
    :type message: str
    """

class AdminIsNotLoginError(Exception):
    """
    Represents an exception raised when an administrative user is not logged in.

    This exception is meant to indicate that a user attempting to perform
    administrative actions has not been authenticated properly or has no
    active session as an admin user.

    :ivar message: A descriptive message providing additional information
        regarding the login error.
    :type message: str
    """

class GroupNotFoundError(Exception):
    """
    Exception raised when a specified group cannot be found.

    This exception is typically used in cases where a requested group does
    not exist in a dataset, collection, or other similar contexts. It is a
    custom error meant to clarify the specific issue of missing groups and
    allows for more granular exception handling.
    """