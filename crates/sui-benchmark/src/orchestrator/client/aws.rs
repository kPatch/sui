use std::{
    collections::HashMap,
    fmt::{Debug, Display},
};

use aws_config::profile::profile_file::{ProfileFileKind, ProfileFiles};
use aws_sdk_ec2::{
    model::{filter, tag, tag_specification, ResourceType},
    types::{Blob, SdkError},
};
use serde::Serialize;

use crate::orchestrator::{
    error::{CloudProviderError, CloudProviderResult},
    settings::Settings,
};

use super::{Client, Instance};

impl<T> From<SdkError<T>> for CloudProviderError
where
    T: Debug + std::error::Error + Send + Sync + 'static,
{
    fn from(e: SdkError<T>) -> Self {
        Self::RequestError(format!("{:?}", e.into_source()))
    }
}

pub struct AwsClient {
    settings: Settings,
    clients: HashMap<String, aws_sdk_ec2::Client>,
}

impl Display for AwsClient {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "AWS EC2 client v{}", aws_sdk_ec2::PKG_VERSION)
    }
}

impl AwsClient {
    const OS_IMAGE: &'static str =
        "Canonical, Ubuntu, 22.04 LTS, amd64 jammy image build on 2023-02-16";

    pub async fn new(settings: Settings) -> Self {
        let profile_files = ProfileFiles::builder()
            .with_file(ProfileFileKind::Credentials, &settings.token_file)
            .with_contents(ProfileFileKind::Config, "[default]\noutput=json")
            .build();

        let mut clients = HashMap::new();
        for region in settings.regions.clone() {
            let sdk_config = aws_config::from_env()
                .region(aws_sdk_ec2::Region::new(region.clone()))
                .profile_files(profile_files.clone())
                .load()
                .await;
            let client = aws_sdk_ec2::Client::new(&sdk_config);
            clients.insert(region, client);
        }

        Self { settings, clients }
    }

    fn format_instance(
        &self,
        region: String,
        aws_instance: &aws_sdk_ec2::model::Instance,
    ) -> Instance {
        Instance {
            id: aws_instance
                .instance_id()
                .expect("AWS instance should have an id")
                .into(),
            region,
            main_ip: aws_instance
                .public_ip_address()
                .unwrap_or_else(|| "0.0.0.0") // Stopped instances do not have an ip address.
                .parse()
                .expect("AWS instance should have a valid ip"),
            tags: vec![self.settings.testbed.clone()],
            plan: format!(
                "{:?}",
                aws_instance
                    .instance_type()
                    .expect("AWS instance should have a type")
            ),
            power_status: format!(
                "{:?}",
                aws_instance
                    .state()
                    .expect("AWS instance should have a state")
                    .name()
                    .expect("AWS status should have a name")
            ),
        }
    }

    /// Query the image id determining the os of the instances.
    /// NOTE: The image id changes depending on the region.
    async fn find_image_id(&self, client: &aws_sdk_ec2::Client) -> CloudProviderResult<String> {
        // Query all images that match the description.
        let request = client.describe_images().filters(
            filter::Builder::default()
                .name("description")
                .values(Self::OS_IMAGE)
                .build(),
        );
        let response = request.send().await?;

        // Parse the response to select the first returned image id.
        response
            .images()
            .map(|images| images.first())
            .flatten()
            .ok_or_else(|| CloudProviderError::RequestError("Cannot find image id".into()))?
            .image_id
            .clone()
            .ok_or_else(|| {
                CloudProviderError::UnexpectedResponse(
                    "Received image description without id".into(),
                )
            })
    }

    async fn create_security_group(&self, client: &aws_sdk_ec2::Client) -> CloudProviderResult<()> {
        // Create a security group (if it doesn't already exist).
        let request = client
            .create_security_group()
            .group_name(&self.settings.testbed)
            .description("Allow all traffic (used for benchmarks).");

        let response = match request.send().await {
            Ok(response) => response,
            Err(e) => {
                let error_message = format!("{e:?}");
                if error_message.to_lowercase().contains("duplicate") {
                    return Ok(());
                } else {
                    return Err(e.into());
                }
            }
        };

        // Extract the group id.
        let group_id = response
            .group_id()
            .expect("AWS security group should have an id");

        // Authorize all traffic on the security group.
        let request = client
            .authorize_security_group_ingress()
            .group_id(group_id)
            .ip_protocol("tcp")
            .ip_protocol("udp")
            .cidr_ip("0.0.0.0/0")
            .from_port(0)
            .to_port(65535);

        request.send().await?;
        Ok(())
    }
}

#[async_trait::async_trait]
impl Client for AwsClient {
    const USERNAME: &'static str = "ubuntu";

    async fn list_instances(&self) -> CloudProviderResult<Vec<Instance>> {
        let filter = filter::Builder::default()
            .name("tag:Name")
            .values(self.settings.testbed.clone())
            .build();

        let mut instances = Vec::new();
        for (region, client) in &self.clients {
            let request = client.describe_instances().filters(filter.clone());
            if let Some(reservations) = request.send().await?.reservations() {
                for reservation in reservations {
                    if let Some(aws_instances) = reservation.instances() {
                        for instance in aws_instances {
                            instances.push(self.format_instance(region.clone(), instance));
                        }
                    }
                }
            }
        }

        Ok(instances)
    }

    async fn start_instances<'a, I>(&self, instances: I) -> CloudProviderResult<()>
    where
        I: Iterator<Item = &'a Instance> + Send,
    {
        let mut instance_ids = HashMap::new();
        for instance in instances {
            instance_ids
                .entry(&instance.region)
                .or_insert_with(Vec::new)
                .push(instance.id.clone());
        }

        for (region, client) in &self.clients {
            client
                .start_instances()
                .set_instance_ids(instance_ids.remove(&region.to_string()))
                .send()
                .await?;
        }
        Ok(())
    }

    async fn stop_instances<'a, I>(&self, instances: I) -> CloudProviderResult<()>
    where
        I: Iterator<Item = &'a Instance> + Send,
    {
        let mut instance_ids = HashMap::new();
        for instance in instances {
            instance_ids
                .entry(&instance.region)
                .or_insert_with(Vec::new)
                .push(instance.id.clone());
        }

        for (region, client) in &self.clients {
            client
                .stop_instances()
                .set_instance_ids(instance_ids.remove(&region.to_string()))
                .send()
                .await?;
        }
        Ok(())
    }

    async fn create_instance<S>(&self, region: S) -> CloudProviderResult<Instance>
    where
        S: Into<String> + Serialize + Send,
    {
        let region = region.into();
        let testbed_id = &self.settings.testbed;

        let client = self.clients.get(&region).ok_or_else(|| {
            CloudProviderError::RequestError(format!("Undefined region {region:?}"))
        })?;

        // Create a security group (if needed).
        self.create_security_group(&client).await?;

        // Query the image id.
        let image_id = self.find_image_id(&client).await?;

        // Create a new instance.
        let tags = tag_specification::Builder::default()
            .tags(
                tag::Builder::default()
                    .key("Name")
                    .value(testbed_id)
                    .build(),
            )
            .resource_type(ResourceType::Instance)
            .build();

        let request = client
            .run_instances()
            .image_id(image_id)
            .instance_type(self.settings.specs.as_str().into())
            .key_name(testbed_id)
            .min_count(1)
            .max_count(1)
            .security_groups(&self.settings.testbed)
            .tag_specifications(tags);

        let response = request.send().await?;
        let instance = &response
            .instances()
            .map(|x| x.first())
            .flatten()
            .expect("AWS instances list should contain instances");

        Ok(self.format_instance(region, instance))
    }

    async fn delete_instance(&self, instance_id: String) -> CloudProviderResult<()> {
        for client in self.clients.values() {
            client
                .terminate_instances()
                .instance_ids(instance_id.clone())
                .send()
                .await?;
        }
        Ok(())
    }

    async fn register_ssh_public_key(&self, public_key: String) -> CloudProviderResult<()> {
        for client in self.clients.values() {
            let request = client
                .import_key_pair()
                .key_name(&self.settings.testbed)
                .public_key_material(Blob::new::<String>(public_key.clone()));

            if let Err(e) = request.send().await {
                let error_message = format!("{e:?}");
                if !error_message.to_lowercase().contains("duplicate") {
                    return Err(e.into());
                }
            }
        }
        Ok(())
    }
}
