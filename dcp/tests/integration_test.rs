#[cfg(test)]
mod tests {
    use chrono::{NaiveTime, Utc};
    use dcp_rs::{Config, Dcp, DcpConfig, GroupConfig};
    use lazy_static::lazy_static;
    use std::collections::BTreeMap;
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::{Arc, Mutex};
    use std::thread;
    use testcontainers::{clients, core::WaitFor, Image};

    #[derive(Default)]
    struct CouchbaseImage {
        volumes: BTreeMap<String, String>,
        env_vars: BTreeMap<String, String>,
    }

    impl Image for CouchbaseImage {
        type Args = ();

        fn name(&self) -> String {
            "couchbase/server".to_owned()
        }

        fn tag(&self) -> String {
            std::env::var("CB_VERSION").unwrap_or_else(|_| "latest".to_owned())
        }

        fn ready_conditions(&self) -> Vec<WaitFor> {
            vec![WaitFor::message_on_stdout(
                "/entrypoint.sh couchbase-server",
            )]
        }

        fn env_vars(&self) -> Box<dyn Iterator<Item = (&String, &String)> + '_> {
            Box::new(self.env_vars.iter())
        }

        fn volumes(&self) -> Box<dyn Iterator<Item = (&String, &String)> + '_> {
            Box::new(self.volumes.iter())
        }

        fn entrypoint(&self) -> Option<String> {
            Some("/config-entrypoint.sh".to_owned())
        }

        fn expose_ports(&self) -> Vec<u16> {
            vec![8091, 8093, 11210]
        }
    }

    #[test]
    fn integration() {
        let _ = env_logger::try_init();

        let username = "user";
        let password = "123456";
        let bucket_name = "dcp-test";

        let mut env_vars = BTreeMap::new();
        env_vars.insert("USERNAME".to_owned(), username.to_owned());
        env_vars.insert("PASSWORD".to_owned(), password.to_owned());
        env_vars.insert("BUCKET_NAME".to_owned(), bucket_name.to_owned());
        env_vars.insert("BUCKET_TYPE".to_owned(), "couchbase".to_owned());
        env_vars.insert("BUCKET_RAMSIZE".to_owned(), "1024".to_owned());
        env_vars.insert("CLUSTER_RAMSIZE".to_owned(), "1024".to_owned());
        env_vars.insert("CLUSTER_INDEX_RAMSIZE".to_owned(), "512".to_owned());
        env_vars.insert("CLUSTER_EVENTING_RAMSIZE".to_owned(), "256".to_owned());
        env_vars.insert("CLUSTER_FTS_RAMSIZE".to_owned(), "256".to_owned());
        env_vars.insert("CLUSTER_ANALYTICS_RAMSIZE".to_owned(), "1024".to_owned());
        env_vars.insert("INDEX_STORAGE_SETTING".to_owned(), "memopt".to_owned());
        env_vars.insert("REST_PORT".to_owned(), "8091".to_owned());
        env_vars.insert("CAPI_PORT".to_owned(), "8092".to_owned());
        env_vars.insert("QUERY_PORT".to_owned(), "8093".to_owned());
        env_vars.insert("FTS_PORT".to_owned(), "8094".to_owned());
        env_vars.insert("MEMCACHED_SSL_PORT".to_owned(), "11207".to_owned());
        env_vars.insert("MEMCACHED_PORT".to_owned(), "11210".to_owned());
        env_vars.insert("SSL_REST_PORT".to_owned(), "18091".to_owned());

        let mut volumes = BTreeMap::new();
        let current_dir = std::env::current_dir().unwrap();

        let entrypoint = current_dir.join("tests/scripts/entrypoint.sh");
        let entrypoint = entrypoint.to_str().unwrap();

        let entrypoint_5 = current_dir.join("tests/scripts/entrypoint_5.sh");
        let entrypoint_5 = entrypoint_5.to_str().unwrap();

        let data = current_dir.join("tests/data/travel-sample.zip");
        let data = data.to_str().unwrap();

        if std::env::var("CB_VERSION")
            .unwrap_or_else(|_| "latest".to_owned())
            .starts_with("5")
        {
            volumes.insert(entrypoint_5.to_owned(), "/config-entrypoint.sh".to_owned());
        } else {
            volumes.insert(entrypoint.to_owned(), "/config-entrypoint.sh".to_owned());
        }
        volumes.insert(
            data.to_owned(),
            "/opt/couchbase/samples/travel-sample.zip".to_owned(),
        );

        let image = CouchbaseImage { env_vars, volumes };

        let docker = clients::Cli::default();

        let container = docker.run(image);

        let config = Config {
            hosts: vec![format!("localhost:{}", container.get_host_port_ipv4(11210))],
            username: username.to_string(),
            password: password.to_string(),
            bucket: bucket_name.to_string(),
            scope_name: "_default".to_string(),
            collection_names: vec!["_default".to_string()],
            dcp: DcpConfig {
                group: GroupConfig {
                    name: "group_name".to_string(),
                },
            },
        };

        lazy_static! {
            static ref COUNTER: Mutex<i32> = Mutex::new(0);
            static ref FINISH: AtomicBool = AtomicBool::new(false);
        }
        let mut start: Box<Option<NaiveTime>> = Box::new(None);

        let dcp = Dcp::new(config).expect("failed to create dcp");
        dcp.add_listener(Box::new(move |_event| {
            let mut counter = COUNTER.lock().unwrap();
            *counter += 1;

            if *counter == 1 {
                *start = Some(Utc::now().time());
            }

            log::debug!("counter: {}", *counter);

            if *counter == 31591 {
                log::info!(
                    "processed with {}ms",
                    (Utc::now().time() - start.as_ref().unwrap()).num_milliseconds()
                );
                FINISH.store(true, Ordering::Relaxed)
            }

            Ok(())
        }));

        let dcp = Arc::new(dcp);
        let inner_dcp = Arc::clone(&dcp);

        thread::spawn(move || {
            if let Err(e) = inner_dcp.start() {
                log::error!("start error: {}", e);
                FINISH.store(true, Ordering::Relaxed);
            }
        });

        while !FINISH.load(Ordering::Relaxed) {
            thread::sleep(std::time::Duration::from_secs(1));
        }

        dcp.stop().expect("failed to stop dcp");
        assert_eq!(*COUNTER.lock().unwrap(), 31591)
    }
}
