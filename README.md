![Travis](https://api.travis-ci.org/daniellawrence/external_naginator.svg)

Install
-------

```sh
mkvirtualenv external_naginator
pip install -r requirements.txt
pip install -e .
```

Configuration
----------------

The config.ini

Testing Locally
---------------------------------

Create a minimal nagios configuration. minimal.cfg
```
cfg_file=/etc/nagios3/commands.cfg
cfg_dir=/etc/nagios-plugins/config
cfg_dir=/home/russell/projects/external_naginator/output/
check_result_path=/home/russell/projects/external_naginator/
```

Edit the config.ini to use this minimal config
```
[nagios]
nagios_cfg=/home/russell/projects/external_naginator/output/minimal.cfg
```

Run external naginator
```
external-naginator --config config.cfg --output-dir output/ --host puppet --port 8080 --update --no-restart
```

Generate and push it to your nagios server
------------------------------------------

    $ pip install fabric
    $ fab deploy
