/*
 * JULEA - Flexible storage framework
 * Copyright (C) 2017-2021 Michael Kuhn
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

/**
 * \file
 **/

#include <julea-config.h>

#include <glib.h>

#include <string.h>

#include <object/jobject.h>
#include <object/jobject-internal.h>

#include <julea.h>

/**
 * \defgroup JObject Object
 *
 * Data structures and functions for managing objects.
 *
 * @{
 **/

struct JObjectOperation
{
	union
	{
		struct
		{
			JObject* object;
			gint64* modification_time;
			guint64* size;
		} status;

		struct
		{
			JObject* object;
		} sync;

		struct
		{
			JObject* object;
			gpointer data;
			guint64 length;
			guint64 offset;
			guint64* bytes_read;
		} read;

		struct
		{
			JObject* object;
			gconstpointer data;
			guint64 length;
			guint64 offset;
			guint64* bytes_written;
		} write;
	};
};

typedef struct JObjectOperation JObjectOperation;

/**
 * A JObject.
 **/
struct JObject
{
	/**
	 * The data server index.
	 */
	guint32 index;

	/**
	 * The namespace.
	 **/
	gchar* namespace;

	/**
	 * The name.
	 **/
	gchar* name;

	/**
	 * The reference count.
	 **/
	gint ref_count;
};

static JBackend* j_object_backend = NULL;
static GModule* j_object_module = NULL;

// FIXME copy and use GLib's G_DEFINE_CONSTRUCTOR/DESTRUCTOR
static void __attribute__((constructor)) j_object_init(void);
static void __attribute__((destructor)) j_object_fini(void);

/**
 * Initializes the object client.
 */
static void
j_object_init(void)
{
	gchar const* object_backend;
	gchar const* object_component;
	gchar const* object_path;

	if (j_object_backend != NULL && j_object_module != NULL)
	{
		return;
	}

	object_backend = j_configuration_get_backend(j_configuration(), J_BACKEND_TYPE_OBJECT);
	object_component = j_configuration_get_backend_component(j_configuration(), J_BACKEND_TYPE_OBJECT);
	object_path = j_configuration_get_backend_path(j_configuration(), J_BACKEND_TYPE_OBJECT);

	if (j_backend_load_client(object_backend, object_component, J_BACKEND_TYPE_OBJECT, &j_object_module, &j_object_backend))
	{
		if (j_object_backend == NULL || !j_backend_object_init(j_object_backend, object_path))
		{
			g_critical("Could not initialize object backend %s.\n", object_backend);
		}
	}
}

/**
 * Shuts down the object client.
 */
static void
j_object_fini(void)
{
	if (j_object_backend == NULL && j_object_module == NULL)
	{
		return;
	}

	if (j_object_backend != NULL)
	{
		j_backend_object_fini(j_object_backend);
		j_object_backend = NULL;
	}

	if (j_object_module != NULL)
	{
		g_module_close(j_object_module);
		j_object_module = NULL;
	}
}

static void
j_object_create_free(gpointer data)
{
	J_TRACE_FUNCTION(NULL);

	JObject* object = data;

	j_object_unref(object);
}

static void
j_object_delete_free(gpointer data)
{
	J_TRACE_FUNCTION(NULL);

	JObject* object = data;

	j_object_unref(object);
}

static void
j_object_status_free(gpointer data)
{
	J_TRACE_FUNCTION(NULL);

	JObjectOperation* operation = data;

	j_object_unref(operation->status.object);

	g_slice_free(JObjectOperation, operation);
}

static void
j_object_sync_free(gpointer data)
{
	J_TRACE_FUNCTION(NULL);

	JObjectOperation* operation = data;

	j_object_unref(operation->sync.object);

	g_slice_free(JObjectOperation, operation);
}

static void
j_object_read_free(gpointer data)
{
	J_TRACE_FUNCTION(NULL);

	JObjectOperation* operation = data;

	j_object_unref(operation->read.object);

	g_slice_free(JObjectOperation, operation);
}

static void
j_object_write_free(gpointer data)
{
	J_TRACE_FUNCTION(NULL);

	JObjectOperation* operation = data;

	j_object_unref(operation->write.object);

	g_slice_free(JObjectOperation, operation);
}

static gboolean
j_object_create_exec(JList* operations, JSemantics* semantics)
{
	J_TRACE_FUNCTION(NULL);

	// FIXME check return value for messages
	gboolean ret = TRUE;

	JBackend* object_backend;
	g_autoptr(JListIterator) it = NULL;
	g_autoptr(JMessage) message = NULL;
	gchar const* namespace;
	gsize namespace_len;
	guint32 index;

	g_return_val_if_fail(operations != NULL, FALSE);
	g_return_val_if_fail(semantics != NULL, FALSE);

	{
		JObject* object;

		object = j_list_get_first(operations);
		g_assert(object != NULL);

		namespace = object->namespace;
		namespace_len = strlen(namespace) + 1;
		index = object->index;
	}

	it = j_list_iterator_new(operations);
	object_backend = j_object_get_backend();

	if (object_backend == NULL)
	{
		/**
		 * Force safe semantics to make the server send a reply.
		 * Otherwise, nasty races can occur when using unsafe semantics:
		 * - The client creates the item and sends its first write.
		 * - The client sends another operation using another connection from the pool.
		 * - The second operation is executed first and fails because the item does not exist.
		 * This does not completely eliminate all races but fixes the common case of create, write, write, ...
		 **/
		message = j_message_new(J_MESSAGE_OBJECT_CREATE, namespace_len);
		j_message_set_semantics(message, semantics);
		j_message_append_n(message, namespace, namespace_len);
	}

	while (j_list_iterator_next(it))
	{
		JObject* object = j_list_iterator_get(it);

		if (object_backend == NULL)
		{
			gsize name_len;

			name_len = strlen(object->name) + 1;

			j_message_add_operation(message, name_len);
			j_message_append_n(message, object->name, name_len);
		}
		else
		{
			gpointer object_handle;

			ret = j_backend_object_create(object_backend, object->namespace, object->name, &object_handle) && ret;
			ret = j_backend_object_close(object_backend, object_handle) && ret;
		}
	}

	if (object_backend == NULL)
	{
		JSemanticsSafety safety;

		gpointer object_connection;

		safety = j_semantics_get(semantics, J_SEMANTICS_SAFETY);
		object_connection = j_connection_pool_pop(J_BACKEND_TYPE_OBJECT, index);
		j_message_send(message, object_connection);

		if (safety == J_SEMANTICS_SAFETY_NETWORK || safety == J_SEMANTICS_SAFETY_STORAGE)
		{
			g_autoptr(JMessage) reply = NULL;

			reply = j_message_new_reply(message);
			j_message_receive(reply, object_connection);

			/* FIXME do something with reply */
		}

		j_connection_pool_push(J_BACKEND_TYPE_OBJECT, index, object_connection);
	}

	return ret;
}

static gboolean
j_object_delete_exec(JList* operations, JSemantics* semantics)
{
	J_TRACE_FUNCTION(NULL);

	gboolean ret = TRUE;

	JBackend* object_backend;
	g_autoptr(JListIterator) it = NULL;
	g_autoptr(JMessage) message = NULL;
	gchar const* namespace;
	gsize namespace_len;
	guint32 index;

	g_return_val_if_fail(operations != NULL, FALSE);
	g_return_val_if_fail(semantics != NULL, FALSE);

	{
		JObject* object;

		object = j_list_get_first(operations);
		g_assert(object != NULL);

		namespace = object->namespace;
		namespace_len = strlen(namespace) + 1;
		index = object->index;
	}

	it = j_list_iterator_new(operations);
	object_backend = j_object_get_backend();

	if (object_backend == NULL)
	{
		message = j_message_new(J_MESSAGE_OBJECT_DELETE, namespace_len);
		j_message_set_semantics(message, semantics);
		j_message_append_n(message, namespace, namespace_len);
	}

	while (j_list_iterator_next(it))
	{
		JObject* object = j_list_iterator_get(it);

		if (object_backend == NULL)
		{
			gsize name_len;

			name_len = strlen(object->name) + 1;

			j_message_add_operation(message, name_len);
			j_message_append_n(message, object->name, name_len);
		}
		else
		{
			gpointer object_handle;

			ret = j_backend_object_open(object_backend, object->namespace, object->name, &object_handle) && ret;
			ret = j_backend_object_delete(object_backend, object_handle) && ret;
		}
	}

	if (object_backend == NULL)
	{
		JSemanticsSafety safety;

		gpointer object_connection;

		safety = j_semantics_get(semantics, J_SEMANTICS_SAFETY);
		object_connection = j_connection_pool_pop(J_BACKEND_TYPE_OBJECT, index);
		j_message_send(message, object_connection);

		if (safety == J_SEMANTICS_SAFETY_NETWORK || safety == J_SEMANTICS_SAFETY_STORAGE)
		{
			g_autoptr(JMessage) reply = NULL;
			guint32 operation_count;

			reply = j_message_new_reply(message);
			j_message_receive(reply, object_connection);

			operation_count = j_message_get_count(reply);

			for (guint i = 0; i < operation_count; i++)
			{
				guint32 status;

				status = j_message_get_4(reply);
				ret = (status == 1) && ret;
			}
		}

		j_connection_pool_push(J_BACKEND_TYPE_OBJECT, index, object_connection);
	}

	return ret;
}

/**
* TODO function description
*/
gboolean
j_object_receive_data_chunks(JMessage* message, JEndpoint* endpoint, JListIterator* it, guint32* reply_operation_count)
{
	J_TRACE_FUNCTION(NULL);

	g_return_val_if_fail(message != NULL, FALSE);
	g_return_val_if_fail(endpoint != NULL, FALSE);
	g_return_val_if_fail(it != NULL, FALSE);

	switch (j_message_get_comm_type(message))
	{
		case J_MSG:
			return j_object_receive_data_chunks_msg(message, endpoint, it, reply_operation_count);
		case J_RDMA:
			return j_object_receive_data_chunks_rdma(message, endpoint, it, reply_operation_count);
		case J_UNDEFINED:
		default:
			g_critical("\nERROR on receiving data chunks on jobject, no valid connection type requested\n");
			return FALSE;
	}
}

/**
* TODO function description
*/
gboolean
j_object_receive_data_chunks_msg(JMessage* message, JEndpoint* jendpoint, JListIterator* it, guint32* reply_operation_count)
{
	gboolean ret;
	ssize_t error;

	error = 0;
	ret = FALSE;

	for (guint i = 0; i < *reply_operation_count && j_list_iterator_next(it); i++)
	{
		JObjectOperation* operation = j_list_iterator_get(it);
		gpointer data = operation->read.data;
		guint64* bytes_read = operation->read.bytes_read;

		guint64 nbytes;

		nbytes = j_message_get_8(message);
		j_helper_atomic_add(bytes_read, nbytes);

		if (nbytes > 0)
		{
			error = fi_recv(j_endpoint_get_endpoint(jendpoint, J_MSG), (void*)data, (size_t)nbytes, NULL, 0, NULL);
			if (error != 0)
			{
				g_critical("\nCLIENT: Error while receiving background write operation for JObjects\nDetails:\n%s\n", fi_strerror((int)error));
				goto end;
			}
			switch (j_endpoint_read_completion_queue(j_endpoint_get_completion_queue(jendpoint, J_MSG, FI_RECV), -1, "CLIENT", "jobject"))
			{
				case J_READ_QUEUE_ERROR:
					g_critical("\nCLIENT: Error reading for completion Event on jobject msg receive data chunks\n");
					goto end;
					break;
				case J_READ_QUEUE_SUCCESS:
					break;
				case J_READ_QUEUE_NO_EVENT:
					break;
				case J_READ_QUEUE_CANCELED:
					goto end;
					break;
				default:
					g_assert_not_reached();
			}
		}
	}

	ret = TRUE;
end:
	return ret;
}

/**
* TODO function description
*/
gboolean
j_object_receive_data_chunks_rdma(JMessage* message, JEndpoint* jendpoint, JListIterator* it, guint32* reply_operation_count)
{
	gboolean ret;
	ssize_t error;

	int* wakeup_buf;

	ret = FALSE;
	error = 0;

	for (guint i = 0; i < *reply_operation_count && j_list_iterator_next(it); i++)
	{
		JObjectOperation* operation = j_list_iterator_get(it);
		gpointer data = operation->read.data;
		guint64* bytes_read = operation->read.bytes_read;

		guint64 nbytes;

		nbytes = j_message_get_8(message);
		j_helper_atomic_add(bytes_read, nbytes);

		if (nbytes > 0)
		{
			//printf("\nJObject:            found key: %lu\n", j_message_get_key(message, i)); //debug

			error = fi_read(j_endpoint_get_endpoint(jendpoint, J_RDMA),
					(void*)data, //target buffer
					(size_t)nbytes, //buffer length
					NULL, // file descriptor
					0, // dest addr (only for unconnected)
					0, // 0-based offset for source memory address
					j_message_get_key(message, i), // corresponding key
					NULL); //context
			if (error != 0)
			{
				g_critical("\nJObject: Error while rdma chunk read. \nDetails:\n%s", fi_strerror(labs(error)));
			}

			switch (j_endpoint_read_completion_queue(j_endpoint_get_completion_queue(jendpoint, J_RDMA, FI_TRANSMIT), -1, "CLIENT", "jbject reading for fi_read completion"))
			{
				case J_READ_QUEUE_ERROR:
					g_critical("\nCLIENT: Error while reading for completion event for fi_read operation on jobject\n");
					break;
				case J_READ_QUEUE_SUCCESS:
					break;
				case J_READ_QUEUE_NO_EVENT:
					break;
				case J_READ_QUEUE_CANCELED:
					goto end;
					break;
				default:
					g_assert_not_reached();
			}
		}
	}

	wakeup_buf = malloc(sizeof(int));

	error = fi_send(j_endpoint_get_endpoint(jendpoint, J_MSG), (void*)wakeup_buf, sizeof(int), NULL, 0, NULL);
	if (error != 0)
	{
		g_critical("\nJObject: Error while sending wakeup Message in loop.\nDetails:\n%s", fi_strerror(labs(error)));
		goto end;
	}
	switch (j_endpoint_read_completion_queue(j_endpoint_get_completion_queue(jendpoint, J_MSG, FI_TRANSMIT), -1, "CLIENT", "jobject"))
	{
		case J_READ_QUEUE_ERROR:
			free(wakeup_buf);
			g_critical("\nCLIENT: Error reading for completion Event for rdma wakeup message on jobject\n");
			goto end;
			break;
		case J_READ_QUEUE_SUCCESS:
			break;
		case J_READ_QUEUE_NO_EVENT:
			break;
		case J_READ_QUEUE_CANCELED:
			free(wakeup_buf);
			goto end;
			break;
		default:
			g_assert_not_reached();
	}

	free(wakeup_buf);
	ret = TRUE;
end:
	j_message_free_keys(message);
	return ret;
}

static gboolean
j_object_read_exec(JList* operations, JSemantics* semantics)
{
	J_TRACE_FUNCTION(NULL);

	// FIXME check return value for messages
	gboolean ret = TRUE;

	JBackend* object_backend;
	JListIterator* it;
	g_autoptr(JMessage) message = NULL;
	JObject* object;
	gpointer object_handle;

	// FIXME
	//JLock* lock = NULL;

	g_return_val_if_fail(operations != NULL, FALSE);
	g_return_val_if_fail(semantics != NULL, FALSE);

	{
		JObjectOperation* operation = j_list_get_first(operations);

		object = operation->read.object;

		g_assert(operation != NULL);
		g_assert(object != NULL);
	}

	it = j_list_iterator_new(operations);
	object_backend = j_object_get_backend();

	if (object_backend == NULL)
	{
		gsize name_len;
		gsize namespace_len;

		namespace_len = strlen(object->namespace) + 1;
		name_len = strlen(object->name) + 1;

		message = j_message_new(J_MESSAGE_OBJECT_READ, namespace_len + name_len);
		j_message_set_semantics(message, semantics);
		j_message_append_n(message, object->namespace, namespace_len);
		j_message_append_n(message, object->name, name_len);
	}
	else
	{
		ret = j_backend_object_open(object_backend, object->namespace, object->name, &object_handle) && ret;
	}

	/*
	if (j_semantics_get(semantics, J_SEMANTICS_ATOMICITY) != J_SEMANTICS_ATOMICITY_NONE)
	{
		lock = j_lock_new("item", path);
	}
	*/

	while (j_list_iterator_next(it))
	{
		JObjectOperation* operation = j_list_iterator_get(it);
		gpointer data = operation->read.data;
		guint64 length = operation->read.length;
		guint64 offset = operation->read.offset;
		guint64* bytes_read = operation->read.bytes_read;

		j_trace_file_begin(object->name, J_TRACE_FILE_READ);

		if (object_backend == NULL)
		{
			j_message_add_operation(message, sizeof(guint64) + sizeof(guint64));
			j_message_append_8(message, &length);
			j_message_append_8(message, &offset);
		}
		else
		{
			guint64 nbytes = 0;

			ret = j_backend_object_read(object_backend, object_handle, data, length, offset, &nbytes) && ret;
			j_helper_atomic_add(bytes_read, nbytes);
		}

		j_trace_file_end(object->name, J_TRACE_FILE_READ, length, offset);
	}

	j_list_iterator_free(it);

	if (object_backend == NULL)
	{
		g_autoptr(JMessage) reply = NULL;
		gpointer object_connection;
		guint32 operations_done;
		guint32 operation_count;

		object_connection = j_connection_pool_pop(J_BACKEND_TYPE_OBJECT, object->index);
		j_message_send(message, object_connection);

		reply = j_message_new_reply(message);

		operations_done = 0;
		operation_count = j_message_get_count(message);

		it = j_list_iterator_new(operations);

		/**
		 * This extra loop is necessary because the server might send multiple
		 * replies per message. The same reply object can be used to receive
		 * multiple times.
		 */
		while (operations_done < operation_count)
		{
			guint32 reply_operation_count;

			j_message_receive(reply, object_connection);

			reply_operation_count = j_message_get_count(reply);

			if (!j_object_receive_data_chunks(reply, (JEndpoint*)object_connection, it, &reply_operation_count))
			{
				g_critical("\nERROR while jobject receiving data chunks\n");
			}

			operations_done += reply_operation_count;
		}

		j_list_iterator_free(it);

		j_connection_pool_push(J_BACKEND_TYPE_OBJECT, object->index, object_connection);
	}
	else
	{
		ret = j_backend_object_close(object_backend, object_handle) && ret;
	}

	/*
	if (lock != NULL)
	{
		// FIXME busy wait
		while (!j_lock_acquire(lock));

		j_lock_free(lock);
	}
	*/

	return ret;
}

static gboolean
j_object_write_exec(JList* operations, JSemantics* semantics)
{
	J_TRACE_FUNCTION(NULL);

	// FIXME check return value for messages
	gboolean ret = TRUE;

	JBackend* object_backend;
	JListIterator* it;
	g_autoptr(JMessage) message = NULL;
	JObject* object;
	gpointer object_handle;

	// FIXME
	//JLock* lock = NULL;

	g_return_val_if_fail(operations != NULL, FALSE);
	g_return_val_if_fail(semantics != NULL, FALSE);

	{
		JObjectOperation* operation = j_list_get_first(operations);

		object = operation->write.object;

		g_assert(operation != NULL);
		g_assert(object != NULL);
	}

	it = j_list_iterator_new(operations);
	object_backend = j_object_get_backend();

	if (object_backend == NULL)
	{
		gsize name_len;
		gsize namespace_len;

		namespace_len = strlen(object->namespace) + 1;
		name_len = strlen(object->name) + 1;

		message = j_message_new(J_MESSAGE_OBJECT_WRITE, namespace_len + name_len);
		j_message_set_semantics(message, semantics);
		j_message_append_n(message, object->namespace, namespace_len);
		j_message_append_n(message, object->name, name_len);
	}
	else
	{
		ret = j_backend_object_open(object_backend, object->namespace, object->name, &object_handle) && ret;
	}

	/*
	if (j_semantics_get(semantics, J_SEMANTICS_ATOMICITY) != J_SEMANTICS_ATOMICITY_NONE)
	{
		lock = j_lock_new("item", path);
	}
	*/

	while (j_list_iterator_next(it))
	{
		JObjectOperation* operation = j_list_iterator_get(it);
		gconstpointer data = operation->write.data;
		guint64 length = operation->write.length;
		guint64 offset = operation->write.offset;
		guint64* bytes_written = operation->write.bytes_written;

		j_trace_file_begin(object->name, J_TRACE_FILE_WRITE);

		/*
		if (lock != NULL)
		{
			j_lock_add(lock, block_id);
		}
		*/

		if (object_backend == NULL)
		{
			j_message_add_operation(message, sizeof(guint64) + sizeof(guint64));
			j_message_append_8(message, &length);
			j_message_append_8(message, &offset);
			j_message_add_send(message, data, length);

			// Fake bytes_written here instead of doing another loop further down
			if (j_semantics_get(semantics, J_SEMANTICS_SAFETY) == J_SEMANTICS_SAFETY_NONE)
			{
				j_helper_atomic_add(bytes_written, length);
			}
		}
		else
		{
			guint64 nbytes = 0;

			ret = j_backend_object_write(object_backend, object_handle, data, length, offset, &nbytes) && ret;
			j_helper_atomic_add(bytes_written, nbytes);
		}

		j_trace_file_end(object->name, J_TRACE_FILE_WRITE, length, offset);
	}

	j_list_iterator_free(it);

	if (object_backend == NULL)
	{
		JSemanticsSafety safety;

		gpointer object_connection;

		safety = j_semantics_get(semantics, J_SEMANTICS_SAFETY);
		object_connection = j_connection_pool_pop(J_BACKEND_TYPE_OBJECT, object->index);
		j_message_send(message, object_connection);

		if (safety == J_SEMANTICS_SAFETY_NETWORK || safety == J_SEMANTICS_SAFETY_STORAGE)
		{
			g_autoptr(JMessage) reply = NULL;
			guint64 nbytes;

			reply = j_message_new_reply(message);
			j_message_receive(reply, object_connection);

			it = j_list_iterator_new(operations);

			while (j_list_iterator_next(it))
			{
				JObjectOperation* operation = j_list_iterator_get(it);
				guint64* bytes_written = operation->write.bytes_written;

				nbytes = j_message_get_8(reply);
				j_helper_atomic_add(bytes_written, nbytes);
			}

			j_list_iterator_free(it);
		}

		j_connection_pool_push(J_BACKEND_TYPE_OBJECT, object->index, object_connection);
	}
	else
	{
		ret = j_backend_object_close(object_backend, object_handle) && ret;
	}

	/*
	if (lock != NULL)
	{
		// FIXME busy wait
		while (!j_lock_acquire(lock));

		j_lock_free(lock);
	}
	*/

	return ret;
}

static gboolean
j_object_status_exec(JList* operations, JSemantics* semantics)
{
	J_TRACE_FUNCTION(NULL);

	// FIXME check return value for messages
	gboolean ret = TRUE;

	JBackend* object_backend;
	JListIterator* it;
	g_autoptr(JMessage) message = NULL;
	gchar const* namespace;
	gsize namespace_len;
	guint32 index;

	g_return_val_if_fail(operations != NULL, FALSE);
	g_return_val_if_fail(semantics != NULL, FALSE);

	{
		JObjectOperation* operation = j_list_get_first(operations);
		JObject* object = operation->status.object;

		g_assert(operation != NULL);
		g_assert(object != NULL);

		namespace = object->namespace;
		namespace_len = strlen(namespace) + 1;
		index = object->index;
	}

	it = j_list_iterator_new(operations);
	object_backend = j_object_get_backend();

	if (object_backend == NULL)
	{
		message = j_message_new(J_MESSAGE_OBJECT_STATUS, namespace_len);
		j_message_set_semantics(message, semantics);
		j_message_append_n(message, namespace, namespace_len);
	}

	while (j_list_iterator_next(it))
	{
		JObjectOperation* operation = j_list_iterator_get(it);
		JObject* object = operation->status.object;
		gint64* modification_time = operation->status.modification_time;
		guint64* size = operation->status.size;

		if (object_backend == NULL)
		{
			gsize name_len;

			name_len = strlen(object->name) + 1;

			j_message_add_operation(message, name_len);
			j_message_append_n(message, object->name, name_len);
		}
		else
		{
			gpointer object_handle;

			ret = j_backend_object_open(object_backend, object->namespace, object->name, &object_handle) && ret;
			ret = j_backend_object_status(object_backend, object_handle, modification_time, size) && ret;
			ret = j_backend_object_close(object_backend, object_handle) && ret;
		}
	}

	j_list_iterator_free(it);

	if (object_backend == NULL)
	{
		g_autoptr(JMessage) reply = NULL;
		gpointer object_connection;

		object_connection = j_connection_pool_pop(J_BACKEND_TYPE_OBJECT, index);
		j_message_send(message, object_connection);

		reply = j_message_new_reply(message);
		j_message_receive(reply, object_connection);

		it = j_list_iterator_new(operations);

		while (j_list_iterator_next(it))
		{
			JObjectOperation* operation = j_list_iterator_get(it);
			gint64* modification_time = operation->status.modification_time;
			guint64* size = operation->status.size;
			gint64 modification_time_;
			guint64 size_;

			modification_time_ = j_message_get_8(reply);
			size_ = j_message_get_8(reply);

			if (modification_time != NULL)
			{
				*modification_time = modification_time_;
			}

			if (size != NULL)
			{
				*size = size_;
			}
		}

		j_list_iterator_free(it);

		j_connection_pool_push(J_BACKEND_TYPE_OBJECT, index, object_connection);
	}

	return ret;
}

static gboolean
j_object_sync_exec(JList* operations, JSemantics* semantics)
{
	J_TRACE_FUNCTION(NULL);

	// FIXME check return value for messages
	gboolean ret = TRUE;

	JBackend* object_backend;
	JListIterator* it;
	g_autoptr(JMessage) message = NULL;
	gchar const* namespace;
	gsize namespace_len;
	guint32 index;

	g_return_val_if_fail(operations != NULL, FALSE);
	g_return_val_if_fail(semantics != NULL, FALSE);

	{
		JObjectOperation* operation = j_list_get_first(operations);
		JObject* object = operation->sync.object;

		g_assert(operation != NULL);
		g_assert(object != NULL);

		namespace = object->namespace;
		namespace_len = strlen(namespace) + 1;
		index = object->index;
	}

	it = j_list_iterator_new(operations);
	object_backend = j_object_get_backend();

	if (object_backend == NULL)
	{
		message = j_message_new(J_MESSAGE_OBJECT_SYNC, namespace_len);
		j_message_set_semantics(message, semantics);
		j_message_append_n(message, namespace, namespace_len);
	}

	while (j_list_iterator_next(it))
	{
		JObjectOperation* operation = j_list_iterator_get(it);
		JObject* object = operation->sync.object;

		if (object_backend == NULL)
		{
			gsize name_len;

			name_len = strlen(object->name) + 1;

			j_message_add_operation(message, name_len);
			j_message_append_n(message, object->name, name_len);
		}
		else
		{
			gpointer object_handle;

			ret = j_backend_object_open(object_backend, object->namespace, object->name, &object_handle) && ret;
			ret = j_backend_object_sync(object_backend, object_handle) && ret;
			ret = j_backend_object_close(object_backend, object_handle) && ret;
		}
	}

	j_list_iterator_free(it);

	if (object_backend == NULL)
	{
		JSemanticsSafety safety;
		gpointer object_connection;

		safety = j_semantics_get(semantics, J_SEMANTICS_SAFETY);
		object_connection = j_connection_pool_pop(J_BACKEND_TYPE_OBJECT, index);
		j_message_send(message, object_connection);

		if (safety == J_SEMANTICS_SAFETY_NETWORK || safety == J_SEMANTICS_SAFETY_STORAGE)
		{
			g_autoptr(JMessage) reply = NULL;

			reply = j_message_new_reply(message);
			j_message_receive(reply, object_connection);

			// FIXME do something with reply
		}

		j_connection_pool_push(J_BACKEND_TYPE_OBJECT, index, object_connection);
	}

	return ret;
}

/**
 * Creates a new object.
 *
 * \code
 * JObject* i;
 *
 * i = j_object_new("JULEA", "JULEA");
 * \endcode
 *
 * \param namespace    A namespace.
 * \param name         An object name.
 *
 * \return A new object. Should be freed with j_object_unref().
 **/
JObject*
j_object_new(gchar const* namespace, gchar const* name)
{
	J_TRACE_FUNCTION(NULL);

	JConfiguration* configuration = j_configuration();
	JObject* object;

	g_return_val_if_fail(namespace != NULL, NULL);
	g_return_val_if_fail(name != NULL, NULL);

	object = g_slice_new(JObject);
	object->index = j_helper_hash(name) % j_configuration_get_server_count(configuration, J_BACKEND_TYPE_OBJECT);
	object->namespace = g_strdup(namespace);
	object->name = g_strdup(name);
	object->ref_count = 1;

	return object;
}

/**
 * Creates a new object.
 *
 * \code
 * JObject* i;
 *
 * i = j_object_new_for_index(index, "JULEA", "JULEA");
 * \endcode
 *
 * \param index        An object server index. Must be less than the return value of j_configuration_get_server_count(configuration, J_BACKEND_TYPE_OBJECT).
 * \param namespace    A namespace.
 * \param name         An object name.
 *
 * \return A new object. Should be freed with j_object_unref().
 **/
JObject*
j_object_new_for_index(guint32 index, gchar const* namespace, gchar const* name)
{
	J_TRACE_FUNCTION(NULL);

	JConfiguration* configuration = j_configuration();
	JObject* object;

	g_return_val_if_fail(namespace != NULL, NULL);
	g_return_val_if_fail(name != NULL, NULL);
	g_return_val_if_fail(index < j_configuration_get_server_count(configuration, J_BACKEND_TYPE_OBJECT), NULL);

	object = g_slice_new(JObject);
	object->index = index;
	object->namespace = g_strdup(namespace);
	object->name = g_strdup(name);
	object->ref_count = 1;

	return object;
}

/**
 * Increases an object's reference count.
 *
 * \code
 * JObject* i;
 *
 * j_object_ref(i);
 * \endcode
 *
 * \param object An object.
 *
 * \return #object.
 **/
JObject*
j_object_ref(JObject* object)
{
	J_TRACE_FUNCTION(NULL);

	g_return_val_if_fail(object != NULL, NULL);

	g_atomic_int_inc(&(object->ref_count));

	return object;
}

/**
 * Decreases an object's reference count.
 * When the reference count reaches zero, frees the memory allocated for the object.
 *
 * \code
 * \endcode
 *
 * \param object An object.
 **/
void
j_object_unref(JObject* object)
{
	J_TRACE_FUNCTION(NULL);

	g_return_if_fail(object != NULL);

	if (g_atomic_int_dec_and_test(&(object->ref_count)))
	{
		g_free(object->name);
		g_free(object->namespace);

		g_slice_free(JObject, object);
	}
}

/**
 * Creates an object.
 *
 * \code
 * \endcode
 *
 * \param name         A name.
 * \param distribution A distribution.
 * \param batch        A batch.
 *
 * \return A new object. Should be freed with j_object_unref().
 **/
void
j_object_create(JObject* object, JBatch* batch)
{
	J_TRACE_FUNCTION(NULL);

	JOperation* operation;

	g_return_if_fail(object != NULL);

	operation = j_operation_new();
	// FIXME key = index + namespace
	operation->key = object;
	operation->data = j_object_ref(object);
	operation->exec_func = j_object_create_exec;
	operation->free_func = j_object_create_free;

	j_batch_add(batch, operation);
}

/**
 * Deletes an object.
 *
 * \code
 * \endcode
 *
 * \param object     An object.
 * \param batch      A batch.
 **/
void
j_object_delete(JObject* object, JBatch* batch)
{
	J_TRACE_FUNCTION(NULL);

	JOperation* operation;

	g_return_if_fail(object != NULL);

	operation = j_operation_new();
	operation->key = object;
	operation->data = j_object_ref(object);
	operation->exec_func = j_object_delete_exec;
	operation->free_func = j_object_delete_free;

	j_batch_add(batch, operation);
}

/**
 * Reads an object.
 *
 * \code
 * \endcode
 *
 * \param object     An object.
 * \param data       A buffer to hold the read data.
 * \param length     Number of bytes to read.
 * \param offset     An offset within #object.
 * \param bytes_read Number of bytes read.
 * \param batch      A batch.
 **/
void
j_object_read(JObject* object, gpointer data, guint64 length, guint64 offset, guint64* bytes_read, JBatch* batch)
{
	J_TRACE_FUNCTION(NULL);

	JObjectOperation* iop;
	JOperation* operation;
	guint64 max_operation_size;

	g_return_if_fail(object != NULL);
	g_return_if_fail(data != NULL);
	g_return_if_fail(length > 0);
	g_return_if_fail(bytes_read != NULL);

	max_operation_size = j_configuration_get_max_operation_size(j_configuration());

	// Chunk operation if necessary
	while (length > 0)
	{
		guint64 chunk_size;

		chunk_size = MIN(length, max_operation_size);

		iop = g_slice_new(JObjectOperation);
		iop->read.object = j_object_ref(object);
		iop->read.data = data;
		iop->read.length = chunk_size;
		iop->read.offset = offset;
		iop->read.bytes_read = bytes_read;

		operation = j_operation_new();
		operation->key = object;
		operation->data = iop;
		operation->exec_func = j_object_read_exec;
		operation->free_func = j_object_read_free;

		j_batch_add(batch, operation);

		data = (gchar*)data + chunk_size;
		length -= chunk_size;
		offset += chunk_size;
	}

	*bytes_read = 0;
}

/**
 * Writes an object.
 *
 * \note
 * j_object_write() modifies bytes_written even if j_batch_execute() is not called.
 *
 * \code
 * \endcode
 *
 * \param object        An object.
 * \param data          A buffer holding the data to write.
 * \param length        Number of bytes to write.
 * \param offset        An offset within #object.
 * \param bytes_written Number of bytes written.
 * \param batch         A batch.
 **/
void
j_object_write(JObject* object, gconstpointer data, guint64 length, guint64 offset, guint64* bytes_written, JBatch* batch)
{
	J_TRACE_FUNCTION(NULL);

	JObjectOperation* iop;
	JOperation* operation;
	guint64 max_operation_size;

	g_return_if_fail(object != NULL);
	g_return_if_fail(data != NULL);
	g_return_if_fail(length > 0);
	g_return_if_fail(bytes_written != NULL);

	max_operation_size = j_configuration_get_max_operation_size(j_configuration());

	// Chunk operation if necessary
	while (length > 0)
	{
		guint64 chunk_size;

		chunk_size = MIN(length, max_operation_size);

		iop = g_slice_new(JObjectOperation);
		iop->write.object = j_object_ref(object);
		iop->write.data = data;
		iop->write.length = chunk_size;
		iop->write.offset = offset;
		iop->write.bytes_written = bytes_written;

		operation = j_operation_new();
		operation->key = object;
		operation->data = iop;
		operation->exec_func = j_object_write_exec;
		operation->free_func = j_object_write_free;

		j_batch_add(batch, operation);

		data = (gchar const*)data + chunk_size;
		length -= chunk_size;
		offset += chunk_size;
	}

	*bytes_written = 0;
}

/**
 * Get the status of an object.
 *
 * \code
 * \endcode
 *
 * \param object    An object.
 * \param batch     A batch.
 **/
void
j_object_status(JObject* object, gint64* modification_time, guint64* size, JBatch* batch)
{
	J_TRACE_FUNCTION(NULL);

	JObjectOperation* iop;
	JOperation* operation;

	g_return_if_fail(object != NULL);

	iop = g_slice_new(JObjectOperation);
	iop->status.object = j_object_ref(object);
	iop->status.modification_time = modification_time;
	iop->status.size = size;

	operation = j_operation_new();
	operation->key = object;
	operation->data = iop;
	operation->exec_func = j_object_status_exec;
	operation->free_func = j_object_status_free;

	j_batch_add(batch, operation);
}

/**
 * Sync an object.
 *
 * \code
 * \endcode
 *
 * \param object    An object.
 * \param batch     A batch.
 **/
void
j_object_sync(JObject* object, JBatch* batch)
{
	J_TRACE_FUNCTION(NULL);

	JObjectOperation* iop;
	JOperation* operation;

	g_return_if_fail(object != NULL);

	iop = g_slice_new(JObjectOperation);
	iop->sync.object = j_object_ref(object);

	operation = j_operation_new();
	operation->key = object;
	operation->data = iop;
	operation->exec_func = j_object_sync_exec;
	operation->free_func = j_object_sync_free;

	j_batch_add(batch, operation);
}

/**
 * Returns the object backend.
 *
 * \return The object backend.
 */
JBackend*
j_object_get_backend(void)
{
	return j_object_backend;
}

/**
 * @}
 **/
