// Copyright (c) 2025 Cloudflare, Inc.
// Licensed under the Apache 2.0 license found in the LICENSE file or at:
//     https://opensource.org/licenses/Apache-2.0

use super::ImplementationError;

#[derive(Debug, PartialEq, Hash, Eq)]
pub enum HTTPFieldParameters {
    /// Indicates whether this HTTP header was both a structured field value and should be strictly serialized in its
    /// signature base representation.
    Sf,
    /// Indicates this HTTP header was a Dictionary structured field value and should be serialized to the `key`'s value
    /// in the signature base representation.
    Key(String),
    /// Indicates all instances of this HTTP header should be wrapped as binary structures before being combined. Typically
    /// only used when an HTTP header appears multple times and cannot be safely concatenated.
    Bs,
    /// Indicates this HTTP header appeared in the trailer, not the header section.
    Tr,
    /// Indicates this HTTP header value was obtained from the request. Typically only used in a signed response.
    Req,
}

#[derive(Debug, PartialEq, Hash, Eq)]
pub struct HTTPFieldParametersSet(pub Vec<HTTPFieldParameters>);

// Represents an HTTP header, informally.
#[derive(Debug, PartialEq, Hash, Eq)]
pub struct HTTPField {
    /// Uniquely identified by name
    pub name: String,
    // Parameters associated with this HTTPField. An ordered container is needed
    // as order of serialization matters.
    pub parameters: HTTPFieldParametersSet,
}

impl TryFrom<sfv::Parameters> for HTTPFieldParametersSet {
    type Error = ImplementationError;

    fn try_from(value: sfv::Parameters) -> Result<Self, Self::Error> {
        let mut output: Vec<HTTPFieldParameters> = vec![];

        for (key, bare_item) in &value {
            match key.as_str() {
                "sf" => {
                    if bare_item
                        .as_boolean()
                        .ok_or(ImplementationError::ParsingError(
                            "sf parameter was present on HTTP field component, but not a boolean"
                                .into(),
                        ))?
                    {
                        output.push(HTTPFieldParameters::Sf);
                    }
                }
                "bs" => {
                    if bare_item
                        .as_boolean()
                        .ok_or(ImplementationError::ParsingError(
                            "bs parameter was present on HTTP field component, but not a boolean"
                                .into(),
                        ))?
                    {
                        output.push(HTTPFieldParameters::Bs);
                    }
                }
                "tr" => {
                    if bare_item
                        .as_boolean()
                        .ok_or(ImplementationError::ParsingError(
                            "tr parameter was present on HTTP field component, but not a boolean"
                                .into(),
                        ))?
                    {
                        output.push(HTTPFieldParameters::Tr);
                    }
                }
                "req" => {
                    if bare_item
                        .as_boolean()
                        .ok_or(ImplementationError::ParsingError(
                            "req parameter was present on HTTP field component, but not a boolean"
                                .into(),
                        ))?
                    {
                        output.push(HTTPFieldParameters::Req);
                    }
                }
                "key" => {
                    let name = bare_item
                        .as_string()
                        .ok_or(ImplementationError::ParsingError(
                            "key parameter was present on HTTP field component, but not a string"
                                .into(),
                        ))?
                        .as_str();
                    output.push(HTTPFieldParameters::Key(name.to_string()));
                }
                parameter_name => {
                    return Err(ImplementationError::ParsingError(format!(
                        "Unexpected parameter `{parameter_name}` when parsing HTTP field component, only sf / bs / key / req / tr allowed"
                    )));
                }
            }
        }
        Ok(HTTPFieldParametersSet(output))
    }
}

impl TryFrom<HTTPFieldParametersSet> for sfv::Parameters {
    type Error = ImplementationError;

    fn try_from(value: HTTPFieldParametersSet) -> Result<Self, Self::Error> {
        let mut parameters = sfv::Parameters::new();
        for param in &value.0 {
            match param {
                HTTPFieldParameters::Sf => {
                    let key = sfv::KeyRef::constant("sf").to_owned();
                    parameters.insert(key, sfv::BareItem::Boolean(true));
                }
                HTTPFieldParameters::Bs => {
                    let key = sfv::KeyRef::constant("bs").to_owned();
                    parameters.insert(key, sfv::BareItem::Boolean(true));
                }
                HTTPFieldParameters::Tr => {
                    let key = sfv::KeyRef::constant("tr").to_owned();
                    parameters.insert(key, sfv::BareItem::Boolean(true));
                }
                HTTPFieldParameters::Req => {
                    let key = sfv::KeyRef::constant("req").to_owned();
                    parameters.insert(key, sfv::BareItem::Boolean(true));
                }
                HTTPFieldParameters::Key(name) => {
                    let key = sfv::KeyRef::constant("key").to_owned();
                    let value = sfv::String::from_string(name.clone())
                        .map_err(|(e, _)| ImplementationError::ImpossibleSfvError(e))?;
                    parameters.insert(key, sfv::BareItem::String(value));
                }
            }
        }
        Ok(parameters)
    }
}

impl TryFrom<HTTPField> for sfv::Item {
    type Error = ImplementationError;

    fn try_from(value: HTTPField) -> Result<Self, Self::Error> {
        let error_message_fragment = format!(
            "Could not coerce HTTP field name `{}` into a valid sfv Item: ",
            &value.name
        );

        Ok(sfv::Item {
            bare_item: sfv::BareItem::String(sfv::String::from_string(value.name).map_err(
                |(_, s)| {
                    ImplementationError::ParsingError(format!("{error_message_fragment}: {s}"))
                },
            )?),
            params: value.parameters.try_into()?,
        })
    }
}

#[derive(Debug, PartialEq, Hash, Eq)]
pub enum QueryParamParameters {
    /// Unique identifier for the query param
    Name(String),
    /// Indicates this HTTP header value was obtained from the request. Typically only used in a signed response.
    Req,
}

#[derive(Debug, PartialEq, Hash, Eq)]
pub enum DerivedComponent {
    /// Represents `@authority` derived component
    Authority {
        /// Indicates this HTTP header value was obtained from the request. Typically only used in a signed response
        req: bool,
    },
    /// Represents `@target-uri` derived component
    TargetUri {
        /// Indicates this HTTP header value was obtained from the request. Typically only used in a signed response
        req: bool,
    },
    /// Represents `@request-target` derived component
    RequestTarget {
        /// Indicates this HTTP header value was obtained from the request. Typically only used in a signed response
        req: bool,
    },
    /// Represents `@method` derived component
    Method {
        /// Indicates this HTTP header value was obtained from the request. Typically only used in a signed response
        req: bool,
    },
    /// Represents `@path` derived component
    Path {
        /// Indicates this HTTP header value was obtained from the request. Typically only used in a signed response
        req: bool,
    },
    /// Represents `@scheme` derived component
    Scheme {
        /// Indicates this HTTP header value was obtained from the request. Typically only used in a signed response
        req: bool,
    },
    /// Represents `@query` derived component
    Query {
        /// Indicates this HTTP header value was obtained from the request. Typically only used in a signed response
        req: bool,
    },
    /// Represents the `@query-params` derived component
    QueryParams { parameters: QueryParamParametersSet },
    /// Represents `@status` derived component
    Status {
        /// Indicates this HTTP header value was obtained from the request. Typically only used in a signed response
        req: bool,
    },
}

#[derive(Debug, PartialEq, Hash, Eq)]
pub struct QueryParamParametersSet(pub Vec<QueryParamParameters>);

impl TryFrom<sfv::Parameters> for QueryParamParametersSet {
    type Error = ImplementationError;

    fn try_from(value: sfv::Parameters) -> Result<Self, Self::Error> {
        let mut output: Vec<QueryParamParameters> = vec![];

        for (key, bare_item) in &value {
            match key.as_str() {
                "req" => {
                    if bare_item
                        .as_boolean()
                        .ok_or(ImplementationError::ParsingError(
                            "`req` parameter was present on `@query-param`, but not a boolean"
                                .into(),
                        ))?
                    {
                        output.push(QueryParamParameters::Req);
                    }
                }
                "name" => {
                    let name = bare_item
                        .as_string()
                        .ok_or(ImplementationError::ParsingError(
                            "`name` parameter was present on `@query-param`, but not a string"
                                .into(),
                        ))?
                        .as_str();
                    output.push(QueryParamParameters::Name(name.to_string()));
                }
                parameter_name => {
                    return Err(ImplementationError::ParsingError(format!(
                        "Unexpected parameter `{parameter_name}` when parsing `@query-param, only name / req allowed"
                    )));
                }
            }
        }
        Ok(QueryParamParametersSet(output.into_iter().collect()))
    }
}

impl TryFrom<QueryParamParametersSet> for sfv::Parameters {
    type Error = ImplementationError;

    fn try_from(value: QueryParamParametersSet) -> Result<Self, Self::Error> {
        let mut sfv_parameters = sfv::Parameters::new();
        for param in &value.0 {
            match param {
                QueryParamParameters::Req => {
                    let key = sfv::KeyRef::constant("req").to_owned();
                    sfv_parameters.insert(key, sfv::BareItem::Boolean(true));
                }
                QueryParamParameters::Name(name) => {
                    let key = sfv::KeyRef::constant("name").to_owned();
                    let value = sfv::String::from_string(name.clone())
                        .map_err(|(_, s)| ImplementationError::ParsingError(format!(
                            "Could not coerce `@query-param` parameter `{}` into a valid sfv Parameter: {}",
                            &name, s
                        )))?;
                    sfv_parameters.insert(key, sfv::BareItem::String(value));
                }
            }
        }
        Ok(sfv_parameters)
    }
}

impl TryFrom<DerivedComponent> for sfv::Item {
    type Error = ImplementationError;

    fn try_from(value: DerivedComponent) -> Result<Self, Self::Error> {
        fn template(name: &str, req: bool) -> Result<sfv::Item, ImplementationError> {
            let mut parameters = sfv::Parameters::new();
            if req {
                let key = sfv::KeyRef::constant("sf").to_owned();
                parameters.insert(key, sfv::BareItem::Boolean(true));
            }

            Ok(sfv::Item {
                bare_item: sfv::BareItem::String(
                    sfv::String::from_string(name.to_string())
                        .map_err(|(e, _)| ImplementationError::ImpossibleSfvError(e))?,
                ),
                params: parameters,
            })
        }

        match value {
            DerivedComponent::Authority { req } => template("@authority", req),
            DerivedComponent::Method { req } => template("@method", req),
            DerivedComponent::Path { req } => template("@path", req),
            DerivedComponent::TargetUri { req } => template("@target-uri", req),
            DerivedComponent::RequestTarget { req } => template("@request-target", req),
            DerivedComponent::Scheme { req } => template("@scheme", req),
            DerivedComponent::Status { req } => template("@status", req),
            DerivedComponent::Query { req } => template("@query", req),
            DerivedComponent::QueryParams { parameters } => {
                let mut sfv_parameters = sfv::Parameters::new();
                for param in &parameters.0 {
                    match param {
                        QueryParamParameters::Req => {
                            let key = sfv::KeyRef::constant("req").to_owned();
                            sfv_parameters.insert(key, sfv::BareItem::Boolean(true));
                        }
                        QueryParamParameters::Name(name) => {
                            let key = sfv::KeyRef::constant("name").to_owned();
                            let value = sfv::String::from_string(name.clone())
                                .map_err(|(e, _)| ImplementationError::ImpossibleSfvError(e))?;
                            sfv_parameters.insert(key, sfv::BareItem::String(value));
                        }
                    }
                }

                Ok(sfv::Item {
                    bare_item: sfv::BareItem::String(
                        sfv::String::from_string("@query-param".to_string())
                            .map_err(|(e, _)| ImplementationError::ImpossibleSfvError(e))?,
                    ),
                    params: parameters.try_into()?,
                })
            }
        }
    }
}

#[derive(Debug, PartialEq, Hash, Eq)]
pub enum CoveredComponent {
    HTTP(HTTPField),
    Derived(DerivedComponent),
}

impl TryFrom<sfv::Item> for CoveredComponent {
    type Error = ImplementationError;

    fn try_from(value: sfv::Item) -> Result<Self, Self::Error> {
        fn fetch_req(
            params: sfv::Parameters,
            component_name: &str,
        ) -> Result<bool, ImplementationError> {
            match params.len() {
                0 => Ok(false),
                1 => {
                    for (key, val) in params {
                        if key.as_str() == "req" {
                            return val.as_boolean().ok_or(ImplementationError::ParsingError(
                                format!(
                                    "`req` parameter was present on `{component_name}`, but not a boolean"
                                ),
                            ));
                        }
                    }
                    Err(ImplementationError::ParsingError(format!(
                        "Encountered another parameter name on `{component_name}`, but only `req` allowed"
                    )))
                }
                2.. => Err(ImplementationError::ParsingError(format!(
                    "Encountered multiple parameter names on `{component_name}`, but only `req` allowed"
                ))),
            }
        }

        match value.bare_item {
            sfv::BareItem::String(inner_string) => {
                let component = match inner_string.as_str() {
                    "@authority" => CoveredComponent::Derived(DerivedComponent::Authority {
                        req: fetch_req(value.params, "@authority")?,
                    }),
                    "@method" => CoveredComponent::Derived(DerivedComponent::Method {
                        req: fetch_req(value.params, "@method")?,
                    }),
                    "@path" => CoveredComponent::Derived(DerivedComponent::Path {
                        req: fetch_req(value.params, "@path")?,
                    }),
                    "@target-uri" => CoveredComponent::Derived(DerivedComponent::TargetUri {
                        req: fetch_req(value.params, "@target-uri")?,
                    }),
                    "@scheme" => CoveredComponent::Derived(DerivedComponent::Scheme {
                        req: fetch_req(value.params, "@scheme")?,
                    }),
                    "@status" => CoveredComponent::Derived(DerivedComponent::Status {
                        req: fetch_req(value.params, "@status")?,
                    }),
                    "@query" => CoveredComponent::Derived(DerivedComponent::Query {
                        req: fetch_req(value.params, "@query")?,
                    }),
                    "@request-target" => CoveredComponent::Derived(DerivedComponent::Query {
                        req: fetch_req(value.params, "@request-target")?,
                    }),
                    "@query-param" => {
                        let component = DerivedComponent::QueryParams {
                            parameters: value.params.try_into()?,
                        };

                        return Ok(CoveredComponent::Derived(component));
                    }
                    field if field.starts_with('@') => {
                        return Err(ImplementationError::ParsingError(format!(
                            "Encountered invald derived component name `{field}`, consult RFC 9421 for valid names"
                        )));
                    }
                    http => {
                        return Ok(CoveredComponent::HTTP(HTTPField {
                            name: http.to_string().to_ascii_lowercase(),
                            parameters: value.params.try_into()?,
                        }));
                    }
                };

                Ok(component)
            }
            other_type => Err(ImplementationError::ParsingError(format!(
                "Expected a stringified sfv::BareItem when parsing into a CoveredComponent, but encountered a different type {other_type:?}"
            ))),
        }
    }
}
