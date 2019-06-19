<?php declare(strict_types=1);
$this->layout('base', ['activeItem' => 'account']); ?>
<?php $this->start('content'); ?>
    <h2><?=$this->t('User Info'); ?></h2>
    <table class="tbl">
        <tr>
            <th><?=$this->t('ID'); ?></th>
            <td><code><?=$this->e($userInfo->getUserId()); ?></code></td>
        </tr>
        <?php if ('DbAuthentication' === $authMethod): ?>
            <tr>
                <th></th>
                <td><a href="passwd"><?=$this->t('Change Password'); ?></a></td>
            </tr>
        <?php endif; ?>

        <?php if (0 !== count($userPermissions)): ?>
        <tr>
            <th><?=$this->t('Permission(s)'); ?></th>
            <td>
                <ul>
                    <?php foreach ($userPermissions as $userPermission): ?>
                        <li><?=$this->e($userPermission); ?></li>
                    <?php endforeach; ?>
                </ul>
            </td>
        </tr>
        <?php endif; ?>
    </table>

    <?php if (0 !== count($authorizedClients)): ?>
    <h2><?=$this->t('Authorized Applications'); ?></h2>
    <table class="tbl">
        <thead>
            <tr><th><?=$this->t('Name'); ?></th><th><?=$this->t('Authorized'); ?> (<?=$this->e(date('T')); ?>)</th><th></th></tr>
        </thead>
        <tbody>
            <?php foreach ($authorizedClients as $client): ?>
            <tr>
                <td><span title="<?=$this->e($client['client_id']); ?>"><?php if ($client['display_name']): ?><?=$this->e($client['display_name']); ?><?php else: ?><em><?=$this->t('Unregistered Client'); ?></em><?php endif; ?></span></td>
                <td><?=$this->d($client['auth_time']); ?></td>
                <td class="text-right">
                    <form method="post" action="removeClientAuthorization">
                        <input type="hidden" name="client_id" value="<?=$this->e($client['client_id']); ?>">
                        <input type="hidden" name="auth_key" value="<?=$this->e($client['auth_key']); ?>">
                        <button><?=$this->t('Revoke'); ?></button>
                    </form>
                </td>
            </tr>
            <?php endforeach; ?>
        </tbody>
    </table>
    <?php endif; ?>
<?php $this->stop(); ?>
