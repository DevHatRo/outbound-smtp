// Package tracing wires OpenTelemetry traces. Tracing is off unless an OTLP
// endpoint is configured through the standard OTEL_* environment variables.
package tracing

import (
	"context"
	"os"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracehttp"
	"go.opentelemetry.io/otel/propagation"
	"go.opentelemetry.io/otel/sdk/resource"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	"go.opentelemetry.io/otel/trace"
)

// Name is the instrumentation scope and default service name.
const Name = "outbound-smtp"

// Tracer returns the relay's tracer; a no-op until Setup enables tracing.
func Tracer() trace.Tracer { return otel.Tracer("github.com/DevHatRo/outbound-smtp") }

// Enabled reports whether an OTLP endpoint is configured.
func Enabled() bool {
	return os.Getenv("OTEL_EXPORTER_OTLP_ENDPOINT") != "" || os.Getenv("OTEL_EXPORTER_OTLP_TRACES_ENDPOINT") != ""
}

// Setup starts exporting traces over OTLP/HTTP when Enabled. The exporter and
// resource read the standard OTEL_* variables (endpoint, headers,
// OTEL_SERVICE_NAME, OTEL_RESOURCE_ATTRIBUTES). The returned function flushes
// and stops the exporter.
func Setup(ctx context.Context, version string) (shutdown func(context.Context) error, err error) {
	if !Enabled() {
		return func(context.Context) error { return nil }, nil
	}
	exp, err := otlptracehttp.New(ctx)
	if err != nil {
		return nil, err
	}
	res, err := resource.New(ctx,
		resource.WithAttributes(
			// Plain keys instead of the semconv package: one less versioned import.
			attribute.String("service.name", Name),
			attribute.String("service.version", version),
		),
		resource.WithFromEnv(), // OTEL_SERVICE_NAME / OTEL_RESOURCE_ATTRIBUTES win
	)
	if err != nil {
		return nil, err
	}
	tp := sdktrace.NewTracerProvider(sdktrace.WithBatcher(exp), sdktrace.WithResource(res))
	otel.SetTracerProvider(tp)
	return tp.Shutdown, nil
}

// Inject returns the W3C traceparent of the span in ctx, or "".
func Inject(ctx context.Context) string {
	c := propagation.MapCarrier{}
	propagation.TraceContext{}.Inject(ctx, c)
	return c["traceparent"]
}

// Extract returns a context that continues the trace described by traceparent.
func Extract(ctx context.Context, traceparent string) context.Context {
	if traceparent == "" {
		return ctx
	}
	return propagation.TraceContext{}.Extract(ctx, propagation.MapCarrier{"traceparent": traceparent})
}

// TraceID returns the trace ID of the span in ctx for log correlation, or "".
func TraceID(ctx context.Context) string {
	if sc := trace.SpanContextFromContext(ctx); sc.HasTraceID() {
		return sc.TraceID().String()
	}
	return ""
}
