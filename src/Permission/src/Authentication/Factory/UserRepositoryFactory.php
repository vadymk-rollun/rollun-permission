<?php
/**
 * @copyright Copyright © 2014 Rollun LC (http://rollun.com/)
 * @license LICENSE.md New BSD License
 */

namespace rollun\permission\Authentication\Factory;

use InvalidArgumentException;
use Psr\Container\ContainerInterface;
use rollun\permission\Authentication\UserRepository;
use Zend\Expressive\Authentication\DefaultUser;
use Zend\Expressive\Authentication\UserInterface;
use Psr\Log\LoggerInterface;

/**
 * Create instance of DataStore (user repository) using 'config' service of $container
 *
 * Config example:
 * <code>
 *  [
 *      DataStoreFactory::class => [
 *          'userDataStore' => 'userDataStoreServiceName'
 *          'roleDataStore' => 'roleDataStoreServiceName'
 *          'userRoleDataStore' => 'userRoleDataStoreServiceName'
 *          'userFactory' => 'userFactoryServiceNameOrCallable', // optional
 *          'config' => [ // optional
 *              // Array of config
 *          ]
 *      ]
 *  ]
 * </code>
 *
 * Class DataStoreAbstractFactory
 * @package rollun\permission\Authentication\UserRepository
 */
class UserRepositoryFactory
{
    const KEY_USER_DATASTORE = 'userDataStore';

    const KEY_ROLE_DATASTORE = 'roleDataStore';

    const KEY_USER_ROLE_DATASTORE = 'userRoleDataStore';

    const KEY_USER_FACTORY = 'userFactory';

    const KEY_CONFIG = 'config';

    /**
     * @param ContainerInterface $container
     * @return UserRepository
     */
    public function __invoke(ContainerInterface $container)
    {
        $config = $container->get('config')[self::class] ?? [];

        if (!isset($config[self::KEY_USER_DATASTORE])) {
            throw new InvalidArgumentException("Missing '" . self::KEY_USER_DATASTORE . "' option");
        }

        if (!isset($config[self::KEY_ROLE_DATASTORE])) {
            throw new InvalidArgumentException("Missing '" . self::KEY_ROLE_DATASTORE . "' option");
        }

        if (!isset($config[self::KEY_USER_ROLE_DATASTORE])) {
            throw new InvalidArgumentException("Missing '" . self::KEY_USER_ROLE_DATASTORE . "' option");
        }

        if (isset($config[self::KEY_USER_FACTORY])) {
            $userFactory = $config[self::KEY_USER_FACTORY];
        } else {
            $userFactory = function (string $identity, array $roles = [], array $details = []): UserInterface {
                return new DefaultUser($identity, $roles, $details);
            };
        }

        if (!is_callable($userFactory) && $container->has($userFactory)) {
            $userFactory = $container->get($userFactory);
        }

        $userDataStore = $container->get($config[self::KEY_USER_DATASTORE]);
        $userRoleDataStore = $container->get($config[self::KEY_USER_ROLE_DATASTORE]);
        $roleDataStore = $container->get($config[self::KEY_ROLE_DATASTORE]);
        $config = $config[self::KEY_CONFIG] ?? [];

        return new UserRepository(
            $userDataStore,
            $userRoleDataStore,
            $roleDataStore,
            $userFactory,
            $config,
            $container->get(LoggerInterface::class)
        );
    }
}
