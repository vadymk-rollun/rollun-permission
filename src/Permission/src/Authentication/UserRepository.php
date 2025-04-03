<?php
/**
 * @copyright Copyright © 2014 Rollun LC (http://rollun.com/)
 * @license LICENSE.md New BSD License
 */

namespace rollun\permission\Authentication;

use InvalidArgumentException;
use rollun\datastore\DataStore\Interfaces\DataStoresInterface;
use rollun\datastore\Rql\RqlQuery;
use rollun\permission\DataStore\AclRolesTable;
use rollun\permission\DataStore\AclUserRolesTable;
use rollun\permission\DataStore\AclUsersTable;
use Xiag\Rql\Parser\Node\Query\ScalarOperator\EqNode;
use Xiag\Rql\Parser\Query;
use Zend\Expressive\Authentication\UserInterface;
use Zend\Expressive\Authentication\UserRepositoryInterface;

class UserRepository implements UserRepositoryInterface
{
    const DEFAULT_USER_ID = AclUserRolesTable::FILED_USER_ID;

    const DEFAULT_PASSWORD = AclUsersTable::FILED_PASSWORD;

    const DEFAULT_ROLE_ID = AclUserRolesTable::FILED_ROLES_ID;

    const DEFAULT_ROLE_NAME = AclRolesTable::FILED_NAME;

    /**
     * @var DataStoresInterface
     */
    protected $users;

    /**
     * @var DataStoresInterface
     */
    protected $userRoles;

    /**
     * @var DataStoresInterface
     */
    protected $roles;

    /**
     * @var callable
     */
    protected $userFactory;

    /**
     * @var array
     */
    protected $config;

    /**
     * DataStore constructor.
     * @param DataStoresInterface $users
     * @param DataStoresInterface $userRoles
     * @param DataStoresInterface $roles
     * @param callable $userFactory
     * @param null $config
     *
     * Require top keys for config:
     * - 'details' array of fields to fetch details
     * - 'userIdInUserRoles' user identifier field name in userRoles datastore
     * - 'userPassword' user password field name in users datastore
     * - 'roleIdInUserRoles' role identifier field name in userRoles datastore
     * - 'roleName' role name field name in roles datastore
     *
     */
    public function __construct(
        DataStoresInterface $users,
        DataStoresInterface $userRoles,
        DataStoresInterface $roles,
        callable $userFactory,
        $config = null,
        $logger
    ) {
        $this->users = $users;
        $this->userRoles = $userRoles;
        $this->roles = $roles;
        $this->setConfigs($config);
        $this->logger = $logger;

        // Provide type safety for the composed user factory.
        $this->userFactory = function (
            string $identity,
            array $roles = [],
            array $details = []
        ) use ($userFactory) : UserInterface {
            return $userFactory($identity, $roles, $details);
        };
    }

    protected function setConfigs($config)
    {
        $this->config = $config;
        $this->config['userIdInUserRoles'] = $this->config['userIdInUserRoles'] ?? self::DEFAULT_USER_ID;
        $this->config['userPassword'] = $this->config['userPassword'] ?? self::DEFAULT_PASSWORD;
        $this->config['roleIdInUserRoles'] = $this->config['roleIdInUserRoles'] ?? self::DEFAULT_ROLE_ID;
        $this->config['roleName'] = $this->config['roleName'] ?? self::DEFAULT_ROLE_NAME;
    }

    /**
     * Try authenticate using $credential and $password
     * The password is supposed to be hashed using 'password_hash'
     *
     * @param string $credential
     * @param string|null $password
     * @return UserInterface|null
     */
    public function authenticate(string $credential, string $password = null): ?UserInterface
    {
        $this->logger->info('Authentication started', ['credential' => $credential]);
        $user = $this->users->read($credential);

        if ($user) {
            if (!$this->config['without_password']) {
                if (!$password || !$this->verifyPassword($user, $password)) {
                    return null;
                }
            }


            return ($this->userFactory)(
                $this->users->getIdentifier(),
                $this->getRoles($credential),
                $this->getDetails($user)
            );
        }

        return null;
    }

    protected function verifyPassword($user, string $password)
    {
        return password_verify($password, $user[$this->config['userPassword']]);
    }

    /**
     * @param array $user
     * @return array
     */
    protected function getDetails(array $user)
    {
        if (!isset($this->config['details'])) {
            return [];
        }

        if (!is_array($this->config['details'])) {
            throw new InvalidArgumentException("Invalid option 'details'");
        }

        $details = [];

        foreach ($this->config['details'] as $field) {
            if (!isset($user[$field])) {
                throw new InvalidArgumentException("Undefined field '$field' in user datastore");
            }

            $details[$field] = $user[$field];
        }

        return $details;
    }

    /**
     * Return user array with roles
     * @param string $userId
     * @return array
     */
    protected function getUser($userId)
    {
        $user = $this->users->read($userId);

        if (isset($user)) {
            $user['roles'] = $this->getRoles($userId);
        }

        return $user;
    }

    /**
     * Return array with user's roles
     * @param string $userId
     * @return array
     */
    protected function getRoles($userId)
    {
        $roles = [];
        $query = new Query();
        $query->setQuery(new EqNode($this->config['userIdInUserRoles'], $userId));
        $result = $this->userRoles->query($query);

        foreach ($result as $item) {
            $role = $this->roles->read($item[$this->config['roleIdInUserRoles']]);

            if (isset($role[$this->config['roleName']])) {
                $roles[] = $role[$this->config['roleName']];
            }
        }

        return $roles;
    }
}
