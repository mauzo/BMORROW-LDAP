use Module::Build;

Module::Build->new(
    module_name		=> "BMORROW::LDAP",
    license		=> "bsd",
    configure_requires	=> {
	"Module::Build"	    => "0.38",
    },
    build_requires	=> {
	"Test::More"	    => "0.96",
    },
    meta_merge		=> {
	resources   => {
	    repository => "http://github.com/mauzo/BMORROW-LDAP",
	    bugtracker => "https://rt.cpan.org/Public/Dist/" .
		"Display.html?Name=BMORROW-LDAP",
	},
    },
)->create_build_script;
